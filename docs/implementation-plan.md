# fastenv Rust Rewrite

## Goal

Rewrite fastenv from Go to idiomatic Rust, replacing the containerd gRPC
dependency with direct kernel interfaces: overlayfs via `rustix`, crun invoked
as a subprocess, and a simple on-disk snapshot registry. The result is a
daemon-free, single-binary CLI with a minimalist dependency tree and
predictable sub-5ms fork latency (no gRPC round-trip).

## Non-goals

- Preserving Go source or translating it line-for-line.
- Retaining containerd ecosystem interop (`ctr`, `nerdctl`, CRI).
- Rootless operation (requires CAP_SYS_ADMIN or root, as before).
- stargz / nydus lazy loading (remains a stretch goal).
- Kubernetes CRI integration.

---

## Phases

### Phase 1 — Rust scaffold and validation

Goal: Working Rust binary with CLI skeleton, structured JSON logger, CI, and a
dev-scout that validates the critical kernel path on target hardware.

- [ ] Dev-scout: validate rustix overlayfs mount, crun direct subprocess exec, flock registry locking on Linux ≥ 5.11
- [ ] Project scaffold: Cargo.toml, clap CLI skeleton, tracing JSON logger, CI (GitHub Actions, self-hosted runner)

### Phase 2 — On-disk registry and base image ingestion

Goal: Bases can be built from a local directory and stored in the content-addressed layout.

- [ ] On-disk registry: registry.json schema, flock-based writer, base/fork CRUD operations
- [ ] build-base: directory → gzip OCI tar layer → content store → base registry entry with meta.json

### Phase 3 — Fork lifecycle

Goal: Fork and discard operate at target latency with a single mount(2) syscall.

- [ ] fork: overlayfs mount via rustix (upper + work dirs + mount call), registry write, p50/p95 latency benchmark
- [ ] discard: overlayfs umount via rustix, delete upper/work dirs, remove fork registry entry

### Phase 4 — Exec and namespace isolation

Goal: Commands run inside an isolated mount/PID namespace using crun directly.

- [ ] exec: OCI bundle construction, crun subprocess, stdio forwarding, exit-code propagation, CPU/memory limits
- [ ] Network isolation: optional loopback-only network namespace via OCI spec netns field

### Phase 5 — Inspection subcommands

Goal: Operators can see exactly what a fork changed and how much disk it used.

- [ ] diff: walk upper/ directory and enumerate changed paths with change type
- [ ] du: measure upper/ directory size, emit structured JSON with quota comparison
- [ ] export-patch: serialize upper/ delta as a tar patch archive

### Phase 6 — Quotas and shared caches

Goal: Hard quota enforcement via kernel project quotas; shared read-only cache layers.

- [ ] Per-fork disk quotas: rustix ioctl FS_IOC_FSSETXATTR after fork, soft/hard mode detection via statfs
- [ ] Shared cache mounts: multi-lower overlayfs dirs for npm/pip/cargo caches from build-base

### Phase 7 — GC, mount-path, and benchmarks

Goal: Operational completeness — lifecycle cleanup, virtiofsd integration, and the bench subcommand.

- [ ] GC: TTL/LRU fork eviction sweep and explicit `fastenv gc` subcommand with registry walk
- [ ] mount-path / unmount: expose fork's merged overlayfs view at a stable host path for virtiofsd
- [ ] Bench: `fastenv bench` subcommand measuring fork and exec latency at p50/p95/p99
