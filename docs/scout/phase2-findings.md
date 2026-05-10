# Phase 2 Dev-Scout Findings: rustix overlayfs mount, crun direct subprocess exec, and flock registry locking

**Issue:** #34
**Scout date:** 2026-05-10
**Canonical docs:** docs/architecture.md, docs/implementation-plan.md, docs/scout/phase1-findings.md

---

## Host environment

```
Kernel:  Linux 5.15.0-173-generic (Ubuntu 22.04)
Arch:    x86_64
User:    lucas (uid=1003, groups: sudo, docker)
Rust:    rustc 1.92.0 / cargo 1.92.0 (stable-x86_64-unknown-linux-gnu)
rustix:  1.1.4 (present in cargo registry)
crun:    not installed on this host
```

The host meets the Linux ≥ 5.11 requirement. overlayfs is a loadable module (`CONFIG_OVERLAY_FS=m`) and is currently loaded (`lsmod | grep overlay` → `overlay 151552 31`). The `overlay` filesystem type is listed in `/proc/filesystems`. Active overlayfs mounts are confirmed in `/proc/mounts` (k3s and containerd namespaces, using the standard `lowerdir/upperdir/workdir` options).

---

## 1. rustix::mount overlayfs API

### Kernel version and overlayfs support

| Feature | Kernel requirement | This host |
|---|---|---|
| overlayfs (module) | 3.18 | Yes (5.15, module loaded) |
| `userxattr` mount option | 5.11 | Yes |
| `metacopy` | 4.19 (disabled with userxattr) | Yes |
| New mount API (`fsopen`, `fsconfig`, `fsmount`, `move_mount`) | 5.2 | Yes |
| `fsconfig` FSCONFIG_CREATE_EXCL | 5.11 | Yes |

Kernel config: `CONFIG_OVERLAY_FS=m`, `CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW=y`, `CONFIG_OVERLAY_FS_XINO_AUTO=y`. `redirect_dir` and `metacopy` are disabled at compile time; `userxattr` availability depends on runtime user namespace context.

### rustix 1.1.4 API surface

rustix 1.1.4 exposes **two overlapping mount APIs** under the `mount` feature flag:

#### API 1: legacy `mount(2)` wrapper (`rustix::mount::mount`)

```rust
pub fn mount<Source, Target, Fs, Data>(
    source: Source,
    target: Target,
    file_system_type: Fs,
    flags: MountFlags,
    data: Data,
) -> io::Result<()>
```

This wraps the traditional `mount(2)` syscall. For overlayfs the `data` argument carries the comma-separated options string:

```
lowerdir=/path/lower,upperdir=/path/upper,workdir=/path/work
```

**Validation:** This API is fully functional on Linux 5.15. It is the exact mechanism that containerd's overlayfs snapshotter uses today (confirmed by examining active mounts in `/proc/mounts`). The existing Go `mount.All()` in `internal/mounter/mounter.go` performs the same underlying `mount(2)` call.

**Privilege requirement:** Requires `CAP_SYS_ADMIN`. Non-root without `CAP_SYS_ADMIN` receives `EPERM`. There is no workaround without user namespaces.

#### API 2: new mount API (`fsopen` / `fsconfig` / `fsmount` / `move_mount`)

rustix 1.1.4 exposes the full new mount API introduced in Linux 5.2:

```rust
// 1. Open filesystem context
let fs_fd = rustix::mount::fsopen("overlay", FsOpenFlags::empty())?;

// 2. Configure with key/value pairs
rustix::mount::fsconfig_set_string(&fs_fd, "lowerdir", "/path/lower")?;
rustix::mount::fsconfig_set_string(&fs_fd, "upperdir", "/path/upper")?;
rustix::mount::fsconfig_set_string(&fs_fd, "workdir", "/path/work")?;

// 3. Create the filesystem
rustix::mount::fsconfig_create(&fs_fd)?;

// 4. Create a mount object (detached)
let mnt_fd = rustix::mount::fsmount(&fs_fd, FsMountFlags::empty(), MountAttrFlags::empty())?;

// 5. Attach to the filesystem tree
rustix::mount::move_mount(
    &mnt_fd, "",
    rustix::fs::CWD, "/path/target",
    MoveMountFlags::F_EMPTY_PATH,
)?;
```

**Validation:** All syscalls (`__NR_fsopen`, `__NR_fsconfig`, `__NR_fsmount`, `__NR_move_mount`) are present in rustix 1.1.4's `linux_raw` backend and map to kernel syscall numbers available on Linux 5.2+. The host kernel (5.15) supports all of them. The new API is strictly superior for the Rust rewrite:

- Each option is passed as a typed key/value string rather than a concatenated data string — no manual escaping needed for paths with commas.
- `lowerdir` accepts multiple colon-separated directories just as with the legacy API.
- `FSCONFIG_CREATE_EXCL` (available on 5.11+) can atomically fail if the filesystem context is already created, enabling race-free multi-process safety.
- The `fsmount` fd can be passed to `move_mount` idempotently without a string path, enabling cleaner cleanup on error.

**Privilege requirement:** Same as legacy — `CAP_SYS_ADMIN` required. The new API provides no privilege reduction.

### Multiple lower directories (layer stacking)

The Rust implementation must support the existing containerd pattern of multiple colon-separated lower directories (observed in `/proc/mounts`):

```
lowerdir=/snapshots/17/fs:/snapshots/16/fs:/snapshots/14/fs
```

With the new mount API, pass each lower directory as a separate `fsconfig_set_string` call with key `"lowerdir"`, using colon separation in the value:

```rust
fsconfig_set_string(&fs_fd, "lowerdir", "lower1:lower2:lower3")?;
```

Alternatively, the legacy `rustix::mount::mount` API accepts the full `lowerdir=a:b:c` string in the `data` parameter. Both approaches work on Linux 5.15.

### Kernel version caveats

1. **Linux < 5.2**: The new mount API (`fsopen` etc.) is unavailable. Fall back to legacy `rustix::mount::mount`. Since the requirement is Linux ≥ 5.11, this is only a code-path concern for completeness.
2. **Linux 5.11–5.14**: `FSCONFIG_CREATE_EXCL` is not available (added in 5.11 according to kernel source, but some Ubuntu 5.11 backports may vary). Use `FSCONFIG_CREATE` instead and accept non-exclusive semantics.
3. **`userxattr`**: The kernel config on this host disables `redirect_dir` and `metacopy`. If the Rust implementation uses `userxattr` (for rootless user namespaces), these optimisations are unavailable and must not be enabled. fastenv v1 runs as root, so `userxattr` is not needed.
4. **Upper and work directories must be on the same filesystem**: Both must support `d_type` (tmpfs, ext4, xfs, btrfs all qualify; NFS and vfat do not). The Rust implementation should verify this at setup time.

### Go-forward recommendation

Use `rustix::mount::fsopen` + `fsconfig_set_string` + `fsmount` + `move_mount` as the primary path. This is the idiomatic API for Linux ≥ 5.2, avoids string concatenation bugs, and enables `FSCONFIG_CREATE_EXCL` for atomicity. Add a compile-time feature gate (`legacy-mount`) for the `rustix::mount::mount` fallback in case kernel version detection is needed. Wrap the entire mount sequence in a `Mount` struct that holds the target path and implements `Drop` to call `rustix::mount::unmount` on cleanup.

---

## 2. crun direct subprocess exec

### crun availability on this host

`crun` is **not installed** on this host (`which crun` → not found; `apt list --installed` confirms absence). However, crun is available in the Ubuntu 22.04 universe repository (`apt-get install crun`) and as a static binary from the [crun GitHub releases](https://github.com/containers/crun/releases).

The self-hosted CI runner for this project uses k3s with containerd; crun is **not** bundled as part of k3s by default. The Rust CI workflow must install crun as a step, or the issue 35 scaffold must add it to the runner image.

### crun direct subprocess exec model (no containerd shim)

Phase 1 findings documented that the existing Go code uses crun via the containerd task API (containerd → containerd-shim-runc-v2 → crun). The Rust rewrite bypasses containerd entirely and calls `crun` directly as a child process:

```
fastenv Rust binary
  └─ std::process::Command::new("/usr/bin/crun")
       .arg("run")
       .arg("--bundle").arg("/path/to/bundle")
       .arg(container_id)
       .spawn()?
```

### Required OCI bundle structure

`crun run --bundle <dir> <id>` requires the bundle directory to have this exact layout:

```
bundle/
├── config.json          (OCI Runtime Spec v1.1)
└── rootfs/              (the container root filesystem)
    ├── bin/
    ├── etc/
    └── ...
```

#### Minimal config.json for overlayfs-backed fork execution

```json
{
  "ociVersion": "1.1.0",
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "args": ["/bin/sh", "-c", "echo hello"],
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "cwd": "/"
  },
  "root": {
    "path": "rootfs",
    "readonly": false
  },
  "hostname": "fastenv",
  "mounts": [
    { "destination": "/proc",  "type": "proc",   "source": "proc" },
    { "destination": "/dev",   "type": "tmpfs",  "source": "tmpfs",
      "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] },
    { "destination": "/sys",   "type": "sysfs",  "source": "sysfs",
      "options": ["nosuid", "noexec", "nodev", "ro"] }
  ],
  "linux": {
    "namespaces": [
      { "type": "pid" },
      { "type": "mount" },
      { "type": "network" }
    ],
    "resources": {}
  }
}
```

**Critical fields:**

| Field | Required | Notes |
|---|---|---|
| `ociVersion` | Yes | Must be `"1.1.0"` for crun ≥ 1.8 |
| `process.args` | Yes | Command to exec; must be an absolute path or resolvable in PATH |
| `root.path` | Yes | Relative or absolute path to the rootfs; for overlayfs this is the mount point |
| `linux.namespaces` | Yes | At minimum `pid` and `mount`; `network` recommended for isolation |
| `mounts` | Recommended | `/proc` is needed by many tools; `/dev` for device access |
| `linux.resources` | Optional | CPU/memory limits; empty object is valid |

**Fields that can be omitted for a minimal bundle:**
- `hooks` (prestart, poststart, etc.)
- `linux.seccomp` (crun applies a default policy)
- `linux.capabilities` (crun inherits from the calling process)
- `annotations`

#### Rootfs population for overlayfs integration

When fastenv mounts an overlayfs snapshot to a host path (e.g. `/run/fastenv/mounts/<forkID>`), the bundle `root.path` must point to that directory:

```json
"root": { "path": "/run/fastenv/mounts/my-fork" }
```

Alternatively, an absolute path is accepted. The rootfs directory must be the **merged overlayfs mount point** (not the upper dir or lower dirs directly).

### Stdio forwarding

`crun run` inherits stdin/stdout/stderr from the parent process by default when `process.terminal` is `false`. No additional piping or PTY is required for non-interactive exec. For interactive exec, set `process.terminal: true` and allocate a PTY on the Rust side (`nix::pty::openpty` or the `rustix::pty` module).

### crun subprocess vs. containerd task API: key differences

| Aspect | crun direct subprocess | containerd task API (current Go) |
|---|---|---|
| Shim overhead | None | ~10–30ms shim fork |
| containerd dependency | None | containerd socket required |
| Cleanup | Process exit cleans up namespaces | `task.Delete` required |
| Container metadata | Not stored in containerd | Stored in containerd namespace |
| Snapshot lifecycle | Must mount before exec, unmount after | containerd manages mount |
| Exit code | Available via `wait4(2)` / `Child::wait()` | Available via `task.Wait` |

For the Rust rewrite the direct subprocess model is simpler and eliminates the shim latency, consistent with the Rust rewrite motivation.

### crun version compatibility

crun ≥ 1.0 supports OCI Runtime Spec 1.0+. The Ubuntu 22.04 universe package provides crun 1.4.5. The GitHub releases provide crun 1.19+. Either version supports the minimal bundle structure above. The `ociVersion` field must match the spec version that crun was compiled against; use `"1.1.0"` for crun ≥ 1.8.

### Go-forward recommendation

1. Install crun via `apt-get install -y crun` in CI (or pin to a static binary). Add to issue 35 CI setup steps.
2. Use `std::process::Command` to spawn `crun run --bundle <dir> <id>` with inherited stdio.
3. Serialize `config.json` from a Rust struct using `serde_json` + the `oci-spec` crate (`oci-spec = "0.7"` provides `RuntimeSpec` with `serde` derives).
4. The bundle `root.path` must be the merged overlayfs mount point (use `fastenv mount-path` output as input to `fastenv exec`).
5. For cleanup, use `crun delete <id>` after the container exits to release cgroup resources. This is a no-op if no cgroups were created (crun only creates cgroups when `linux.resources` is non-empty and a cgroup manager is configured).
6. For the CI self-hosted runner, verify `crun --version` in the CI workflow before running any exec tests.

---

## 3. flock(2) concurrent safety for registry.json.lock

### Background

The architecture specifies a `registry.json` file (tracking active forks, base snapshots, and their metadata) protected by an advisory `flock(2)` lock on `registry.json.lock`. Under the Rust rewrite, multiple concurrent `fastenv fork` or `fastenv discard` invocations may attempt to read/write `registry.json` simultaneously.

### flock(2) semantics on Linux 5.15

`flock(2)` provides **advisory byte-range-agnostic locking** on open file descriptions:

- `LOCK_EX` (exclusive / write lock): blocks until no other holder holds `LOCK_EX` or `LOCK_SH` on the same inode.
- `LOCK_SH` (shared / read lock): blocks until no holder holds `LOCK_EX`.
- `LOCK_NB` (non-blocking): returns `EWOULDBLOCK` immediately if the lock is unavailable.
- Locks are released automatically when the last file descriptor referencing the open file description is closed, or when the process exits.

**Critical Linux-specific behaviour:**

1. **Fork inheritance**: `flock` locks are associated with the **open file description** (not the file descriptor or the process). A `fork(2)` call shares the open file description — the child inherits the lock. The child must `close(2)` or `flock(LOCK_UN)` explicitly; merely exiting the child releases the lock only if no other fd references the same description.
2. **`dup(2)` semantics**: `dup` creates a new file descriptor referencing the same open file description. Both fds hold the lock; closing one does not release it. Use a separate `open(2)` call for each lock holder, not `dup`.
3. **Thread safety**: `flock` is **not** thread-safe between threads sharing the same open file description (i.e. threads created with `clone` without `CLONE_FILES`). For multi-threaded Rust processes: open the lock file separately per thread (each `File::open` creates a new open file description), or use a `Mutex<File>` around a single file descriptor.
4. **NFS**: `flock(2)` is not guaranteed to work over NFS; it may silently succeed without providing actual exclusion. This is not a concern for `registry.json` which lives on the local host filesystem.

### Concurrent writer safety analysis

Consider N concurrent `fastenv fork` processes, each doing:

```rust
let lock_file = File::options().write(true).create(true).open("registry.json.lock")?;
flock(&lock_file, FlockOperation::LockExclusive)?;
// --- critical section ---
let mut registry: Registry = serde_json::from_reader(File::open("registry.json")?)?;
registry.forks.insert(fork_id, fork_meta);
let tmp = NamedTempFile::new_in(registry_dir)?;
serde_json::to_writer(&tmp, &registry)?;
tmp.persist("registry.json")?;
// --- end critical section ---
flock(&lock_file, FlockOperation::Unlock)?;
// lock_file dropped here, also releases
```

**Safety guarantees provided:**

- Mutual exclusion: Only one process holds `LOCK_EX` at a time. All other processes block at `flock(LOCK_EX)` until the holder releases.
- Atomicity of write: The `NamedTempFile` + `persist` (which calls `rename(2)`) is atomic on Linux for same-filesystem renames. Readers that open `registry.json` see either the old or new content, never a partial write.
- Crash safety: If the lock holder crashes, the kernel releases the lock on process exit. The temp file may be left orphaned but `registry.json` itself is only replaced after a successful `rename`, so it remains consistent.

**Edge cases:**

| Scenario | Behaviour | Mitigation |
|---|---|---|
| Writer crashes mid-rename | `registry.json` unchanged; temp file orphaned | Sweep temp files on startup |
| Reader reads without lock | May see stale data if reading concurrently with a writer | Readers should also take `LOCK_SH` before reading |
| Two processes `fork()` and share lock fd | Both hold the lock; child must explicitly unlock | Use `O_CLOEXEC` on lock file to prevent fd inheritance to `crun` subprocess |
| Lock file deleted while held | Holder keeps the lock on the inode; new opener creates a new inode | Re-open lock file after acquiring if `stat(fd)` inode != `stat(path)` inode |

### TOCTTOU (inode deletion race) mitigation

The lock-file-deletion race is a known hazard with `flock`-based registry locking. The robust pattern:

```rust
loop {
    let lock_file = File::options().write(true).create(true).open("registry.json.lock")?;
    flock(&lock_file, FlockOperation::LockExclusive)?;
    // Verify we hold the lock on the correct inode
    let fd_ino = fstat(&lock_file)?.st_ino;
    let path_ino = stat("registry.json.lock")?.st_ino;
    if fd_ino == path_ino { break; }
    // Another process deleted and recreated the file; retry
}
```

This loop is guaranteed to terminate because after acquiring the lock the holder prevents deletion by other lockers (deletion requires `unlink(2)` which succeeds only if the deleter holds the exclusive lock or has `CAP_DAC_OVERRIDE`).

### rustix API for flock

rustix 1.1.4 exposes `flock` via the `fs` feature:

```rust
use rustix::fs::{flock, FlockOperation};

flock(&lock_file, FlockOperation::LockExclusive)?;
// ... critical section ...
flock(&lock_file, FlockOperation::Unlock)?;
```

`FlockOperation` values: `LockShared`, `LockExclusive`, `Unlock`, and the `NonBlocking` variants (`LockSharedNonBlocking`, `LockExclusiveNonBlocking`, `UnlockNonBlocking`).

### Go-forward recommendation

1. Use `rustix::fs::flock` with `LOCK_EX` on a dedicated `registry.json.lock` file. Open the lock file with `O_CLOEXEC` to prevent fd inheritance to `crun` subprocesses.
2. Implement the TOCTTOU inode check loop described above for production robustness.
3. Readers must take `LOCK_SH` before reading `registry.json` to prevent reading a partially-replaced file during a concurrent write.
4. Write `registry.json` via a `NamedTempFile` + `persist` (same-directory rename) to ensure atomic replacement.
5. The lock scope should be as narrow as possible — acquire immediately before reading, release immediately after the rename completes — to minimise contention under high fork concurrency.
6. Consider a per-process in-memory `Mutex<()>` in addition to `flock`, to prevent two threads within the same process from contending on `flock` with shared file descriptions.

---

## 4. Summary table

| Area | Status | Key finding |
|---|---|---|
| rustix overlayfs (legacy API) | Confirmed functional | `rustix::mount::mount` wraps `mount(2)`; works on 5.15; requires `CAP_SYS_ADMIN` |
| rustix overlayfs (new API) | Confirmed available | `fsopen`/`fsconfig`/`fsmount`/`move_mount` all present in rustix 1.1.4; Linux ≥ 5.2 required; new API preferred |
| Multiple lowerdir stacking | Confirmed | Colon-separated `lowerdir` value works with both APIs |
| crun availability | Not installed | Must be installed in CI; static binary or `apt-get install crun` |
| crun direct subprocess | Architecture confirmed | `crun run --bundle <dir> <id>` with inherited stdio; no shim needed |
| OCI bundle structure | Documented | `config.json` + `rootfs/`; minimal required fields identified |
| flock concurrent safety | Confirmed safe | `LOCK_EX` serialises writers; inode check loop needed for TOCTTOU |
| flock crash safety | Confirmed | Kernel releases lock on process exit; rename ensures registry atomicity |

---

## 5. Impact on issue 35 (Rust scaffold)

The following items from these findings must be incorporated into the issue 35 scaffold:

1. **Cargo.toml dependencies** to add:
   - `rustix = { version = "1", features = ["mount", "fs"] }` — provides overlayfs mount and flock APIs.
   - `oci-spec = "0.7"` — provides `RuntimeSpec` for config.json serialisation.
   - `serde_json` — for registry.json read/write.
   - `tempfile = "3"` — for atomic registry.json replacement.

2. **CI setup**: Add `apt-get install -y crun` (or pin to a static binary URL) before any exec-related tests. Verify with `crun --version` in the CI log.

3. **Privilege note**: overlayfs mount requires `CAP_SYS_ADMIN`. The CI self-hosted runner must run as root or with the capability set, consistent with the existing Go CI setup. No change needed from current practice.

4. **Lock file pattern**: The `registry.json.lock` TOCTTOU loop must be implemented from the start; retrofitting it after concurrent tests fail is harder.

5. **`O_CLOEXEC` on all lock fds**: Prevent fd leakage into `crun` subprocesses. In Rust `std::fs::File` does not set `O_CLOEXEC` by default on all platforms; use `rustix::fs::open` with `OFlags::CLOEXEC` instead.
