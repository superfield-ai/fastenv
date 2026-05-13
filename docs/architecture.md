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
- The host never mounts a writable project workspace directly for untrusted
  code.
- Outputs leave the VM only through controlled export paths.
- Cross-tenant writable caches are disallowed.

---

## 8. Open Decisions

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
