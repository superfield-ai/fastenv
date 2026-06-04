# Architecture

## 1. Overview

fastenv is a host/control-plane plus project-VM system. The host runs the
scheduler, Firecracker supervisor, secret broker, artifact validator, and
policy monitors. Each project gets one Firecracker microVM as the durable
security boundary. Inside that VM, agent work runs in `crun` containers.

The architecture is intentionally layered:

```text
Physical host
  - scheduler
  - Firecracker supervisor
  - image/cache service
  - artifact collector
  - host eBPF monitor
  - host cgroups / jailer / seccomp

Project microVM
  - one repo / tenant / project security domain
  - guest kernel
  - project filesystem
  - project-local package caches
  - project-local network policy
  - optional guest eBPF monitor

Agent container inside VM
  - crun
  - overlayfs CoW workspace
  - private mount and PID namespaces
  - restricted capabilities
  - per-agent workspace and temp/build dirs
```

The host does not execute project code directly.

The current codebase mirrors that split through an explicit boundary module:

- `HostControlPlane` names the host-side orchestration surface.
- `GuestRuntime` names the workspace-engine primitive surface that the host
  can delegate to while the project-VM split is still being carved out.
- The current CLI routes through `LocalHostControlPlane` and
  `LocalGuestRuntime` so the seam stays visible in code and tests instead of
  remaining implicit inside the command handlers.

---

## 2. Trust Boundaries

### Host boundary

Goal: a compromised project must not compromise the host or other projects.

Host responsibilities:

- schedule projects and agent runs
- start and stop Firecracker VMs
- broker secrets
- collect artifacts and patches
- enforce host-side policy and network attachment
- observe host-level behavior through eBPF

Host eBPF programs run in the host kernel. They watch the Firecracker/jailer
boundary, host files, host devices, and host network paths associated with the
project VM.

### Project boundary

Goal: one project VM contains one trust domain, such as a repo, tenant, or
other explicitly chosen grouping.

Project VM responsibilities:

- hold the guest kernel boundary
- maintain project-local caches
- apply project-level network policy
- optionally run guest eBPF for audit and policy

Guest eBPF programs run in the guest kernel. They observe and constrain
activity inside the project VM, including agent containers, without replacing
the VM boundary itself.

### Agent boundary

Goal: one agent should not corrupt another agent's workspace or runtime state.

Agent container responsibilities:

- isolate filesystem writes with overlayfs
- isolate the process tree
- apply per-agent resource controls
- keep temp and build directories separate

---

## 3. Filesystem Layout

The host should see only VM-level state, not live project workspaces.

Host-side layout:

```text
/var/lib/fastenv/vms/<project-id>/
  firecracker.sock
  kernel
  rootfs.img
  workspace.img
  logs/
  artifacts/
  state.json
```

Guest-side layout:

```text
/project/
  repo.git
  worktrees/
    <agent-id>/
  containers/
    <agent-id>/
      upper/
      work/
      merged/
  cache/
  artifacts/
```

The guest owns internal worktree, cache, and container layout. The host only
deals with the VM image, exported artifacts, and policy data.

---

## 4. Execution Model

### Project VM lifecycle

The project VM is long-lived relative to individual agent runs. It may be
warm-started or kept alive to amortize Firecracker boot cost within a trust
domain.

### Agent run lifecycle

An agent run starts by creating a `crun` container inside the VM, attaching an
overlayfs workspace, and applying resource limits. When the run ends, the
container is destroyed, but the project VM remains available for the next
agent.

### Output flow

Agent outputs should leave the VM through a controlled channel:

- patches
- logs
- test reports
- build artifacts

The host should validate or at least gate those outputs before merging or
publishing them.

---

## 5. Policy Model

### Network

Network policy is hierarchical:

- host decides whether a VM has network access at all
- project VM decides project-level access
- agent container may further restrict access for a run

Useful modes include:

- none
- package-mirror-only
- allowlist
- full-egress-audited

### Secrets

Secrets must be short-lived and scoped to the minimum necessary trust domain.
They should be injected on demand and never baked into base images or mounted
from host home directories.

### eBPF

eBPF is a monitoring and policy layer, not the sandbox itself.

- host eBPF watches the Firecracker/jailer boundary and host resources
- guest eBPF watches agent behavior inside the VM

The two layers are intentionally separate:

- host eBPF is loaded by the host kernel and only sees host-side state
- guest eBPF is loaded by the guest kernel and only sees guest-side state

### Seccomp

Seccomp is a syscall-surface filter applied at **both** boundary layers as
defense-in-depth. It narrows the reachable kernel surface; it does not replace
the boundary it wraps (see §7).

- **VMM layer (host side).** Firecracker installs a built-in seccomp-bpf
  allowlist on the VMM process so that a guest-to-VMM escape (a device-emulation
  or vmexit bug) is contained before it reaches the host. This wraps the
  *hardware* boundary, not the guest.
- **Agent layer (guest side).** Each `crun` container should carry a seccomp
  profile in its OCI `config.json` (`linux.seccomp`) to drop the exotic-syscall
  tail (`ptrace`, `bpf`, `keyctl`, `io_uring` setup, raw/packet sockets, etc.)
  that namespaces alone leave reachable inside the guest kernel.

Seccomp policy is hierarchical, mirroring the network model — each layer may
only **tighten** the layer above it, never loosen it:

- host baseline: a default profile applied to every guest VM and every agent
  container
- project VM: a project-level profile that may narrow the host baseline
- agent container: a per-run profile that may narrow further

**Current state.** The VMM-layer filter is live — Firecracker is spawned without
`--no-seccomp`, so its default VMM allowlist applies whenever a real VM boots
(`src/host_control_plane.rs`). The **agent-layer profile is not yet wired**:
`build_oci_config` in `src/exec.rs` emits `linux.{namespaces, resources}` only,
with no `linux.seccomp` field, and raw `crun` applies no default profile when
the field is absent — so agent containers currently run with their syscalls
**unconfined** by seccomp. Closing this is the target; the hierarchical resolver
above describes the intended end state, not the present one.

---

## 6. Cache Strategy

Caching should stay within the right trust domain:

- host global cache: templates, kernels, read-only mirror data
- project VM cache: project-local package caches and Git objects
- agent container cache: per-run temp and build outputs

Writable caches must not be shared across tenants. Shared read-only seeds are
acceptable when they do not weaken the trust boundary.

---

## 7. Security and Isolation Invariants

The architecture depends on these invariants:

- Firecracker is the project boundary.
- `crun` is the agent boundary.
- eBPF observes and constrains, but does not replace the VM boundary.
- host and guest eBPF remain distinct kernel-local policy planes.
- seccomp narrows the syscall surface at both the VMM and agent layers, but
  wraps each boundary as defense-in-depth — it never replaces it. Per-layer
  seccomp policy may only tighten, never loosen, the layer above.
- The host never mounts a writable project workspace directly for untrusted
  code.
- Outputs leave the VM only through controlled export paths.
- Cross-tenant writable caches are disallowed.

---

## 8. Container Lifecycle

### ContainerRuntime trait

The `ContainerRuntime` trait (defined in `src/container_runtime.rs`) is the
sole lifecycle boundary for OCI containers in fastenv. All callers go through
this trait — no direct subprocess or library calls exist outside the backend
implementations. This boundary enables:

1. Swapping backends for benchmarking without touching callers.
2. Mock implementations for unit tests.
3. Identical tracing spans regardless of backend.

```rust
pub trait ContainerRuntime: Send + Sync {
    fn backend_name(&self) -> &'static str;
    fn create(&self, fork_id: &str, bundle_dir: &Path) -> Result<()>;
    fn start(&self, fork_id: &str, bundle_dir: &Path) -> Result<i32>;
    fn delete(&self, fork_id: &str) -> Result<()>;
}
```

All implementations emit identical tracing span names and field keys:

| Span name          | Fields                                         |
|--------------------|------------------------------------------------|
| `container.create` | `fork_id`, `backend`, `duration_ms`            |
| `container.start`  | `fork_id`, `backend`, `duration_ms`, `exit_code` |
| `container.delete` | `fork_id`, `backend`, `duration_ms`            |

### CrunBackend

`CrunBackend` (always available, no feature flag required) invokes the `crun`
OCI runtime as a subprocess. This is the production default.

- `create()`: validates that `config.json` is present in the bundle directory.
- `start()`: spawns `crun run --bundle <bundle_dir> <fork_id>` and returns the
  exit code.
- `delete()`: no-op — `crun run` handles its own cleanup. Emits the expected
  tracing span for parity.

### YoukiBackend

`YoukiBackend` (enabled by `--features youki`) calls the `libcontainer` Rust
crate in-process. `libcontainer` is the library that powers the `youki` binary.
No `youki` binary is required in PATH.

- `create()`: calls `libcontainer::container::builder::ContainerBuilder::new()`
  to create the container state on disk under `root_path/<fork_id>/`.
- `start()`: loads container state with `Container::load()` and calls
  `Container::start()` in-process.
- `delete()`: loads container state and calls `Container::delete()` in-process.
  Best-effort: logs a warning on failure.

### Benchmark design rationale

The purpose of the two-backend design is a valid crun-vs-youki latency
comparison. The comparison is only meaningful if subprocess overhead is isolated
to `CrunBackend` only. `CrunBackend` spawns a subprocess for every `start()`
call; `YoukiBackend` does not. By compiling `libcontainer` as an optional
dependency (`youki = ["dep:libcontainer"]` in `Cargo.toml`), the youki
execution path eliminates subprocess spawn cost and exec overhead. The measured
latency difference reflects pure OCI runtime overhead, not process spawn cost.

The benchmark suite in `benches/container_runtime.rs` and
`benches/e2e_runtime.rs` measures per-operation latency and full E2E path.
Results are written to `docs/benchmarks/container-runtime-comparison.json`.

---

## 9. Open Decisions

### OD-1 - Boundary key

Should the project VM be keyed by repo, tenant, organization, user, or some
explicit combination? The answer depends on the operator's trust model, and
the platform should allow the boundary to be chosen deliberately.

### OD-2 - Workspace transfer

Should a project use copy-in/copy-out by default, or a shared filesystem when
the project is trusted? The safe default is copy-in/copy-out or a project-local
disk image, with shared filesystem only for explicitly trusted domains.

### OD-3 - VM reuse

How aggressively should the scheduler reuse warm project VMs? Reuse improves
latency, but the reuse policy must not blur trust domains.

### OD-4 - Cache seeding

Which caches can be seeded host-side as read-only inputs, and which must remain
project-local? The rule should be conservative: seed only data that does not
create writable cross-tenant sharing.
