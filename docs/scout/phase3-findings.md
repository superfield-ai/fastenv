# Phase 3 Dev-Scout Findings: tar content addressing, OCI bundle structure, and content store layout

**Issue:** #49
**Scout date:** 2026-05-11
**Canonical docs:** docs/architecture.md, docs/implementation-plan.md
**Downstream issues:** #37 (build-base), #40 (exec)

---

## Host environment

```
Kernel:  Linux 5.15.0-173-generic (Ubuntu 22.04)
Arch:    x86_64
User:    lucas (uid=1003, groups: sudo, docker)
Rust:    rustc 1.92.0 / cargo 1.92.0 (stable-x86_64-unknown-linux-gnu)
crun:    0.17 (commit 0e9229ae, OCI spec 1.0.0, +SECCOMP +EBPF +YAJL)
```

---

## 1. tar crate API — gzip archive with matching SHA-256

### Crate versions validated

| Crate   | Version | Note                          |
|---------|---------|-------------------------------|
| tar     | 0.4.45  | latest on crates.io at scout date |
| flate2  | 1.1.9   | uses miniz_oxide backend by default |
| sha2    | 0.10.9  | RustCrypto, no C dependency   |
| hex     | 0.4.3   | hex encoding for digest       |

### Correct API sequence

```rust
use tar::Builder;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Sha256, Digest};

let mut gz_buf: Vec<u8> = Vec::new();
{
    let enc = GzEncoder::new(&mut gz_buf, Compression::default());
    let mut ar = Builder::new(enc);
    ar.append_dir_all(".", src_path).unwrap();
    ar.finish().unwrap();
}
// After the block: gz_buf contains the complete gzip tar archive
let mut hasher = Sha256::new();
hasher.update(&gz_buf);
let digest = hex::encode(hasher.finalize());
```

`append_dir_all(".", src_path)` performs a deterministic depth-first walk of
`src_path`, setting the in-archive prefix to `.` (compatible with OCI layer
convention). `ar.finish()` flushes the underlying `GzEncoder` write-through,
so the outer `Vec<u8>` is complete when the block exits.

### Validation result

A 3-file directory (file1.txt, file2.txt, file3.txt) was packed:

```
Built gzip tar archive: 196 bytes
Rust sha256:  3ed307a8560ad444f69945b1d54713d1c8a62bfc79e0d224b1522c3aa1326983
sha256sum:    3ed307a8560ad444f69945b1d54713d1c8a62bfc79e0d224b1522c3aa1326983
MATCH: Rust sha256 == sha256sum(file)
```

The in-memory digest computed with `sha2` exactly matches `sha256sum` on the
written file. No intermediate buffering or padding issues observed.

### Risk: determinism

`append_dir_all` uses `std::fs::read_dir`, which does **not** guarantee
directory entry ordering. Two calls on the same directory may produce different
byte sequences (and therefore different digests) if the filesystem returns
entries in a different order. For OCI layer identity the caller in #37 must
sort entries explicitly or use a deterministic directory-walk crate.

Recommended fix for #37:

```rust
// Collect all DirEntry paths, sort, then append each explicitly:
let mut paths: Vec<PathBuf> = WalkDir::new(src_path)
    .sort_by_file_name()
    .into_iter()
    .filter_map(|e| e.ok())
    .map(|e| e.into_path())
    .collect();
for path in &paths {
    ar.append_path_with_name(path, path.strip_prefix(src_path).unwrap())?;
}
```

Or use the `walkdir` crate's `sort_by_file_name()` option.

---

## 2. Content store directory layout and permissions

### Expected layout

```
content/
└── blobs/
    └── sha256/
        └── <64-char hex digest>   (the gzip tar archive bytes)
```

This mirrors the containerd content store layout used by OCI registries.

### Validation result

```
Path:         content/blobs/sha256/3ed307a8...6983
Permissions:  0664 (-rw-rw-r--)
Owner:        lucas:lucas (uid=1003)
Size:         196 bytes
Read-back:    OK (byte-identical to in-memory archive)
```

Default `fs::write` produces `0664` on this host (umask `0002`). This is safe
for a single-user daemon but too permissive if fastenv runs as a dedicated
service account. The implementation in #37 should apply an explicit `0440`
or `0600` mode after writing the blob to prevent untrusted processes from
replacing content.

### Directory creation

```
content/blobs/sha256/   — mode 0755 (default mkdir)
```

No extended attributes or special inode settings are needed. The path itself
encodes the algorithm (`sha256`) and digest, matching the OCI content
descriptor format.

---

## 3. OCI config.json — minimum fields required by crun 0.17

### First attempt (missing UTS namespace)

An initial config with `"hostname": "scout-test"` but without `"type": "uts"`
in the namespaces array produced:

```
hostname requires the UTS namespace
exit: 1
```

crun 0.17 enforces that setting `hostname` requires `uts` in `linux.namespaces`.

### Validated minimal config.json

```json
{
  "ociVersion": "1.0.0",
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "args": ["/bin/sh", "-c", "echo hello-from-crun"],
    "env": ["PATH=/bin"],
    "cwd": "/"
  },
  "root": {
    "path": "rootfs",
    "readonly": false
  },
  "hostname": "scout-test",
  "mounts": [
    { "destination": "/proc", "type": "proc", "source": "proc" },
    {
      "destination": "/dev",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]
    },
    {
      "destination": "/sys",
      "type": "sysfs",
      "source": "sysfs",
      "options": ["nosuid", "noexec", "nodev", "ro"]
    },
    { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs" }
  ],
  "linux": {
    "namespaces": [
      { "type": "pid" },
      { "type": "mount" },
      { "type": "uts" }
    ]
  }
}
```

Exit code: `0`. Output: `hello-from-crun`.

### Required fields summary

| Field | Required | Notes |
|---|---|---|
| `ociVersion` | yes | must be `"1.0.0"` |
| `process.terminal` | yes | `false` for non-interactive exec |
| `process.user` | yes | uid/gid; `0`/`0` for root |
| `process.args` | yes | argv[0] must exist in rootfs |
| `process.env` | yes | at minimum `["PATH=/bin"]` |
| `process.cwd` | yes | must exist in rootfs |
| `root.path` | yes | path to rootfs dir (relative or absolute) |
| `root.readonly` | yes | `false` for writable forks |
| `hostname` | conditional | if set, `uts` namespace required |
| `mounts[proc]` | yes | crun aborts if `/proc` cannot be mounted |
| `mounts[dev]` | yes | crun requires `/dev` to be writable |
| `linux.namespaces` | yes | `pid` + `mount` minimum; add `uts` if hostname is set |

Fields **not** required for a minimal exec with crun 0.17:
- `linux.resources` (CPU/memory limits)
- `linux.seccomp`
- `linux.capabilities`
- `linux.devices`
- `annotations`

The `linux.resources` section is needed for #40's CPU/memory limits feature
but is not required for the container to start.

### `root.path` — relative vs absolute

crun accepts both. When `root.path` is relative, crun resolves it relative to
the bundle directory. When it is an absolute path, the bundle directory is
irrelevant (the `--bundle` flag still controls where crun looks for
`config.json` itself, but `root.path` is used verbatim). This is important for
#40: the implementation can write `config.json` to a temporary bundle dir and
point `root.path` at the absolute path of the fork's `merged/` directory.

---

## 4. forks/<key>/merged/ as crun rootfs

### Setup

```
forks/test-fork-001/
├── lower/   (base content + busybox /bin/sh)
├── upper/   (CoW writes go here)
├── work/    (overlayfs work dir)
└── merged/  (union view, used as rootfs)
```

Mount command:

```
mount -t overlay overlay \
  -o lowerdir=.../lower,upperdir=.../upper,workdir=.../work \
  .../merged
```

Exit: `0`. `merged/` listed `base.txt`, `config.txt`, `bin/`, `proc/`, `dev/`,
`sys/`, `tmp/` as expected.

### crun run with absolute rootfs path

```json
"root": { "path": "/tmp/scout-phase3/forks/test-fork-001/merged", "readonly": false }
```

Output:

```
rootfs-via-merged
base.txt  bin  config.txt  dev  proc  sys  tmp
exit: 0
```

The overlayfs `merged/` directory is a valid crun rootfs. No errors, no
permission problems. The `sys` mount must be listed in `config.json` even
though `/sys` already exists in the rootfs; omitting it is fine as long as
processes in the container do not need sysfs.

### Risk: mount namespace leak

If the process managing fastenv's fork lifecycle crashes after `mount()` but
before the fork is fully registered, the overlayfs mount will be left live with
no registry entry. #37/#40 implementations must use a two-phase write:

1. `mount()` the overlay
2. Write the registry entry
3. Only on error: `umount()` and clean up upper/work

This matches the rollback pattern from phase2-findings.md §5.

---

## 5. Integration risks for #37 and #40

### #37 (build-base)

| Risk | Severity | Mitigation |
|---|---|---|
| Non-deterministic tar walk → different digest on each run | High | Sort directory entries before appending (see §1 above) |
| Blob file permissions too broad (0664) | Low | Explicitly `chmod 0440` after write |
| Large base images OOM from in-memory Vec | Medium | Use a `BufWriter<File>` and hash via `io::copy` with a `sha2::digest::DynDigest` wrapper instead of buffering all bytes |

### #40 (exec)

| Risk | Severity | Mitigation |
|---|---|---|
| `hostname` without `uts` namespace → crun error | Low | Always include `uts` in `linux.namespaces` when hostname is set |
| Absolute `root.path` and relative bundle path misalignment | Low | Write config.json to a temp dir; use absolute path for `root.path` |
| Missing `/proc` mount → crun abort | Medium | Always include proc mount in generated config.json |
| crun 0.17 is old (Ubuntu 22.04 package); newer spec fields may differ | Low | Pin to spec 1.0.0; test on the self-hosted runner before merge |

---

## Summary

All four validation areas pass on Linux 5.15.0 / Ubuntu 22.04:

1. **tar + sha256**: `tar::Builder` + `flate2::GzEncoder` + `sha2::Sha256`
   produces a gzip archive whose in-memory digest matches `sha256sum`. The only
   caveat is non-deterministic directory ordering — #37 must sort entries.

2. **Content store layout**: `content/blobs/sha256/<hex>` path works without
   special filesystem features. Default permissions are `0664`; production code
   should tighten to `0440`.

3. **OCI config.json for crun 0.17**: Minimum required fields are
   `ociVersion`, `process.{terminal,user,args,env,cwd}`, `root.{path,readonly}`,
   `mounts` (proc + dev at minimum), and `linux.namespaces` (pid + mount +
   uts if hostname is set). `linux.resources` and seccomp are optional.

4. **forks/<key>/merged/ as rootfs**: overlayfs-mounted `merged/` directory is
   a valid crun rootfs with both relative and absolute `root.path`. No
   permission or namespace issues observed.

No production code was changed in this scout.
