# Architecture

## 1. Overview

fastenv is a Linux daemon-free CLI that provides OCI-native copy-on-write
workspace forking for AI agents. It creates isolated execution environments in
≤100ms p95 by applying overlayfs mounts directly via kernel syscalls, without
routing through a container daemon. Each fork is a thin writable layer on top
of a shared read-only base; only writes are tracked per fork. fastenv is
implemented in Rust and targets a minimalist dependency footprint: no gRPC, no
container daemon, no protobuf — only kernel interfaces and a small set of
well-audited crates.

---

## 2. Technology Stack

| Layer | Choice | Rationale | Source |
|-------|--------|-----------|--------|
| Language | Rust (stable) | Predictable latency (no GC pauses), zero-cost syscall wrappers, single static binary, org-wide Rust consolidation | Superfield org direction |
| CLI | `clap` (derive API) | Idiomatic Rust CLI; feature-equivalent to cobra | This doc |
| Syscall interface | `rustix` | Safe, audited Linux syscall bindings; covers `mount(2)`, `statfs(2)`, `ioctl` (project quota), `flock(2)` | This doc |
| Async runtime | `tokio` | Required for concurrent fork operations; gates exec I/O forwarding | This doc |
| Structured logging | `tracing` + `tracing-subscriber` (JSON layer) | Structured JSON output matching existing log schema; zero-overhead when disabled | README, Go prototype |
| Serialization | `serde` + `serde_json` | Registry file, snapshot metadata, CLI JSON output | This doc |
| OCI types | `oci-spec` | OCI image config and manifest types; avoids hand-rolling spec structs | This doc |
| Tar / layer I/O | `tar` crate | OCI layer archive read/write for `build-base` | This doc |
| Content addressing | `sha2` + `hex` | SHA-256 digests for OCI layer and config blobs | This doc |
| OCI runtime | `crun` (external binary) | OCI-compliant, fast (~2–3× faster exec init than runc), no shim required in direct-invoke mode | Phase 1 scout §2 |
| Quota enforcement | `rustix` ioctl (`FS_IOC_FSSETXATTR`) | Kernel project-quota assignment on ext4/xfs; soft fallback when unavailable | scout §4, quota-prerequisites.md |

---

## 3. Data Layout

All fastenv state lives under a configurable root (default `/var/lib/fastenv`):

```
/var/lib/fastenv/
  bases/<base-key>/
    lower/          ← extracted base layer tree (read-only; bind-mounted as overlayfs lower)
    meta.json       ← OCI image config digest, creation timestamp, labels
  forks/<fork-key>/
    upper/          ← per-fork writable delta (overlayfs upper dir)
    work/           ← overlayfs work dir (must be same filesystem as upper/)
    merged/         ← optional mount point for mount-path subcommand (virtiofsd)
    meta.json       ← base ref, quota bytes, quota mode, creation timestamp, labels
  registry.json     ← index of all bases and forks; write-locked via flock(2)
  content/
    blobs/sha256/<digest>  ← content-addressed OCI layer and config blobs
```

### Fork operation (kernel path)

```
mkdir upper/ work/
mount -t overlay -o lowerdir=<base>/lower,upperdir=upper,workdir=work none merged/
```

This is a single `mount(2)` syscall. No daemon round-trip. Target: < 5ms.

### Exec operation (crun direct)

1. Construct a minimal OCI bundle under a temp directory: `config.json` (OCI
   runtime spec) + `rootfs/` symlink pointing to the fork's `merged/` dir.
2. `crun run --bundle <tmpdir> <fork-key>`.
3. Wait for exit; forward stdio. Delete bundle dir on exit.
4. The fork's overlayfs snapshot is **not** affected by exec lifecycle.

---

## 4. Architectural Constraints

**C1 — No container daemon dependency.**
fastenv must operate without containerd, Docker, or any other container daemon
running on the host. All snapshot and mount operations go directly through
kernel interfaces (`mount(2)`, overlayfs). Rationale: minimalist deployment,
no gRPC overhead, eliminates daemon as operational dependency.

**C2 — OCI compliance.**
The exec path must use a conformant OCI runtime (crun). OCI image format (tar
layers, content-addressed manifests) must be preserved for the `build-base`
output so that images are portable. No custom kernel patches, no bespoke
runtimes (README non-goals).

**C3 — Linux kernel ≥ 5.11.**
Required for `userxattr` overlayfs option (`user.overlay.*` xattrs), which is
needed for rootless-compatible configurations. fastenv probes overlayfs support
at startup and exits with a clear error if unavailable. Source: Phase 1 scout §3.

**C4 — CAP_SYS_ADMIN or root.**
`mount(2)` on Linux requires elevated privilege. fastenv documents this as a
hard requirement. Rootless operation via user namespaces is not a v1 goal.

**C5 — Minimalist dependencies.**
No gRPC, no protobuf, no async HTTP client, no container SDK. Each crate
dependency requires explicit justification. The dependency tree must remain
auditable. Prefer `rustix` over raw `unsafe` syscalls; prefer `serde_json`
over a custom serialization format.

**C6 — Advisory locking on registry writes.**
All writes to `registry.json` must hold an exclusive `flock(2)` lock on a
`.lock` file in the fastenv root. Reads may proceed without a lock but must
tolerate stale data from an in-progress write. This allows multiple concurrent
`fastenv exec` invocations without registry corruption.

**C7 — Snapshot and task lifecycles are independent.**
The fork's overlayfs snapshot persists across exec invocations. `fastenv exec`
creates and destroys the OCI bundle and crun process; it does not modify the
snapshot. Only `fastenv discard` removes the snapshot.

**C8 — Structured JSON logging.**
All log output must be newline-delimited JSON matching the schema established
by the Go prototype: `level`, `ts`, `msg`, and operation-specific fields
(e.g. `fork_id`, `creation_latency`, `quota_mode`). Human-readable output is
not a goal.

---

## 5. Open Decisions

**OD-1 — Registry format: JSON file vs. SQLite.**
A single `registry.json` with `flock` is simple and has no dependency. SQLite
via `rusqlite` provides atomic transactions and is safer under concurrent
writers. Recommendation: start with JSON + flock; migrate to SQLite if
concurrent writer contention is measured in benchmarks.

**OD-2 — crun invocation: subprocess vs. libcrun.**
`crun` can be invoked as an external subprocess (current approach) or linked
as a C library via FFI. Subprocess is simpler and keeps crun upgradeable
independently. FFI eliminates one process fork and stdio pipe. Recommendation:
subprocess for v1; FFI is a future optimisation if exec latency testing shows
the process fork is on the critical path.

**OD-3 — Hard quota: ioctl vs. external tool.**
Project quota assignment after overlayfs `Prepare` can be done via
`ioctl(FS_IOC_FSSETXATTR)` (in-process, no external binary) or by shelling
out to `xfs_quota` / `tune2fs`. Recommendation: `ioctl` via `rustix` for
reliability and to avoid external tool dependency. Source: scout §4.

**OD-4 — Shared cache layers.**
The Go prototype committed per-type cache directories (npm, pip, cargo) as
separate named snapshot layers shared read-only across forks. In the direct
overlayfs model, this maps to additional lower dirs in the overlayfs mount
(overlayfs supports multiple lower dirs as a colon-separated list). Decide
in the `build-base` implementation issue whether to support multi-lower
cache dirs or defer to v2.

---

## 6. What Containerd Provided (and What Replaced It)

The Go prototype used containerd as an intermediary. This table records what
each containerd subsystem did and what replaces it, to prevent re-introduction
of the dependency.

| Containerd subsystem | Role in prototype | Replacement |
|---|---|---|
| Snapshotter gRPC API | Snapshot create/delete/list | Direct `mount(2)` + `registry.json` |
| Content store | Content-addressed blob storage | `content/blobs/sha256/<digest>` directory |
| Image service | Named image → manifest mapping | `bases/<key>/meta.json` |
| Task API + shim | Exec lifecycle management | `crun run` subprocess |
| GC machinery | Reference-graph garbage collection | Registry walk + discard |
| `archive.Diff` helper | Directory → OCI tar layer | `tar` crate + `sha2` |
| `mount.All()` helper | Apply mount descriptors | `rustix::mount::mount()` |

The only features containerd provided that are not replaced in v1:
- Cross-image OCI layer deduplication (content store sharing across base images)
- Ecosystem interop with `ctr` / `nerdctl`
- Kubernetes CRI integration (stretch goal, remains open)

---

## 7. Source Coverage

| Source | Rules applied | Notes |
|--------|---------------|-------|
| README.md | C2, C4, OD-4; fork lifecycle, exec isolation, quota, GC, benchmarks | Functions as PRD; no formal `docs/prd.md` exists |
| docs/scout/phase1-findings.md | C3 (kernel ≥ 5.11), OD-3 (quota ioctl), crun path, overlayfs prereqs | Phase 1 scout is the primary technical reference |
| docs/quota-prerequisites.md | OD-3, C1 (quota detection without containerd path) | References containerd paths; updated by this doc |
| Conversation (Rust migration) | C1 (no containerd), C5 (minimalist deps), language choice | Architectural direction set in session |
