# fastenv

**Project-isolated workspace runtime for AI agents.**

fastenv gives each project a durable Firecracker microVM boundary and runs
individual agent tasks inside `crun` containers within that VM. The result is
strong project isolation with cheap per-agent fan-out.

The canonical product requirements live in [docs/prd.md](docs/prd.md), and the
target architecture lives in [docs/architecture.md](docs/architecture.md).

---

## The problem

AI agents need isolated environments to run in parallel. Plain host containers
give concurrency, but they still share the host kernel directly. fastenv uses a
microVM per project to raise the trust boundary, then uses containers inside
the VM to keep per-agent execution cheap.

fastenv is designed for AI vendor software such as Claude Code, Codex, and
similar coding agents.

---

## What fastenv isolates

**Isolated per project VM**
- Project code and dependency scripts
- Project-local caches
- Project-local network policy
- Project-local secrets, if any

**Isolated per agent container inside the VM**
- Filesystem writes through copy-on-write overlays
- Process trees and temp directories
- Per-agent resource limits

**Observed and governed by the host**
- Firecracker lifecycle and jailer policy
- Network attachment and egress policy
- Artifact export and patch validation
- Host-side eBPF monitoring

fastenv is a security boundary for semi-untrusted project workloads. The host
is not expected to run project code directly.

---

## Design principle

fastenv is not trying to turn host containers into the tenant boundary.

```text
Host / control plane
  └── Project VM: one Firecracker microVM per repo / tenant / project
        └── Agent sandboxes: crun containers inside the VM
              └── Process/tool execution
```

That hierarchy keeps the project boundary at the VM layer and the agent
boundary at the container layer. eBPF is used for policy and observability.

---

## Architecture

### Host control plane

The host owns:

- project scheduling
- Firecracker VM lifecycle
- jailer and seccomp policy
- secret brokering
- artifact validation
- host-side eBPF monitoring
- network attachment policy

No project code executes directly on the host.

### Project VM

Each project gets one Firecracker microVM for the relevant trust domain. The
VM contains:

- a guest kernel
- project-local filesystem state
- project-local caches
- project-local network policy
- an optional guest eBPF monitor

The VM is the durable security boundary. Whether the trust domain is a repo,
tenant, organization, or user should be chosen explicitly.

### Agent sandbox

Inside the VM, `crun` containers provide cheap per-agent isolation:

- private mount namespace
- private PID namespace
- overlayfs copy-on-write workspace
- restricted capabilities
- per-agent temp and build directories

This layer is optimized for fan-out and workspace cleanliness, not for
protecting the host on its own.

---

## Success criteria

- Project boundaries are explicit and enforced by the VM layer.
- Multiple agents can run concurrently inside a project VM without stomping on
  each other.
- The host only receives validated outputs, not live trust in guest
  workspaces.
- Agent sandbox creation inside an existing project VM remains fast enough for
  interactive loops.

---

## Context

fastenv is a component of [Superfield](https://github.com/superfield-ai/superfield-cli-ts) - an Agent Integrated Development Environment. The role of fastenv is to provide the isolation and execution substrate for agent work, while the control plane retains policy and artifact ownership.

Related:
- [`superfield-ai/sharp`](https://github.com/superfield-ai/sharp) - agent-native VCS, backwards-compatible with Git
- [`superfield-ai/nexum`](https://github.com/superfield-ai/nexum) - self-improving synthetic corpus for agent skills
