# fastenv

**OCI-native ultrafast workspace forking for AI agents.**

fastenv lets AI agents (Codex, Claude, etc.) fork isolated workspaces in **≤100ms p95** using OCI container primitives — no file copies, no git worktrees, no disk exhaustion.

---

## The problem

AI agents need isolated environments to run in parallel. The naive approach — copying the workspace per agent — is too slow and too expensive at scale. Git worktrees solve disk duplication but not dependency isolation. VMs solve isolation but not latency.

fastenv solves all three: instant forks, isolated execution, minimal disk overhead.

---

## Design principle

We are not building a custom filesystem.

> **OCI-native copy-on-write environment branching using container snapshotters**

```
OCI image (prepared workspace)
        ↓
containerd snapshot (base)
        ↓
copy-on-write snapshot (fork)
        ↓
OCI runtime (exec inside fork)
```

Each fork is a **containerd snapshot layer**, not a filesystem copy. The base image is content-addressed and shared across all forks. Only writes are tracked, per fork, in a thin writable layer.

---

## Usage

### 1. Build a base workspace image

```bash
fastenv build-base .
```

Produces an OCI image containing: repo checkout, installed dependencies, toolchain, optionally pre-populated caches. Immutable and reusable.

### 2. Fork it

```bash
fastenv fork --base <image> --name <fork-id>
```

Creates a writable snapshot layer on top of the base. No file copying. Target: p50 ≤ 50ms, p95 ≤ 100ms.

### 3. Execute inside the fork

```bash
fastenv exec <fork-id> -- <cmd>
```

Runs with isolated mount namespace, isolated PID namespace, optional network isolation, and configurable CPU/memory limits. Uses crun via containerd for fast startup.

### 4. Inspect changes

```bash
fastenv diff <fork-id>
fastenv du <fork-id>          # writable layer size only — not base image
fastenv export-patch <fork-id>
```

### 5. Discard

```bash
fastenv discard <fork-id>
```

Instant. Snapshot GC removes all traces.

---

## Full lifecycle

```bash
fastenv build-base .
fastenv fork --base my-workspace --name agent-1
fastenv exec agent-1 -- pytest
fastenv diff agent-1
fastenv discard agent-1
```

---

## Architecture

### Snapshotter

Uses the containerd snapshot API. Supported snapshotters:

| Snapshotter | Notes |
| --- | --- |
| **overlayfs** | Default. Kernel-native, widely supported |
| **stargz** | Lazy-loading — files fetched on demand, not on fork |
| **nydus** | Content-addressed + deduplication |

Lazy snapshotters are preferred where available — fork latency is not gated on materializing the full base image.

### Shared caches

Dependencies are never duplicated across forks. Package caches (`/cache/npm`, `/cache/pip`, `/cache/cargo`) are mounted as shared content-addressed layers. Reads are served from the shared mount; writes go through a controlled per-fork cache layer.

### Disk management

- **Per-fork quotas**: writable layer size limits enforced at the snapshotter level
- **Delta tracking**: `fastenv du` measures only the writable layer delta
- **GC**: TTL-based cleanup, LRU eviction of unused forks, periodic snapshot garbage collection

---

## Success criteria

- [ ] Fork creation ≤ 100ms p95
- [ ] Disk usage per fork proportional only to changes made in that fork
- [ ] No full workspace duplication across forks
- [ ] Multiple concurrent forks without disk exhaustion
- [ ] OCI-compliant implementation (no custom kernel patches, no bespoke runtimes)

---

## Benchmarks

The benchmark suite measures:

- Fork creation latency (p50, p95, p99)
- Exec start latency
- Writable layer growth rate
- Disk usage per fork
- Maximum concurrent forks

Tested against: small repo (<100 files), medium repo (~10k files), large repo (>100k files).

---

## Stretch goals

- **Warm fork pool** — pre-created snapshot inventory for sub-10ms fork creation
- **CRIU integration** — process snapshot/restore to pre-warm agent execution state
- **Remote lazy-loaded base images** — stargz/nydus remote base, no local pull required
- **Kubernetes CRI integration** — fastenv as a CRI plugin for cluster-scale agent workloads

---

## Non-goals

- Custom filesystem implementation
- Non-OCI runtimes
- Git-based isolation (no worktrees)
- VM-based isolation (no Firecracker)

---

## Context

fastenv is a component of [Superfield](https://github.com/superfield-ai/superfield-cli-ts) — an Agent Integrated Development Environment. In the Superfield Phase 2 architecture, fastenv replaces external CI runners with an embedded feedback loop: agents get a fresh isolated environment per test run, with results in milliseconds rather than minutes.

Related:
- [`superfield-ai/sharp`](https://github.com/superfield-ai/sharp) — agent-native VCS, backwards-compatible with Git
- [`superfield-ai/nexum`](https://github.com/superfield-ai/nexum) — self-improving synthetic corpus for agent skills
