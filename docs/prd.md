# fastenv Product Requirements

## 1. Product Vision

fastenv is a workspace platform for AI coding agents. Its primary job is to
give each project a durable Firecracker microVM boundary, while keeping the
agent/task boundary cheap by running `crun` containers inside that VM.

The intent is to separate trust domains cleanly:

- Host and control plane manage scheduling, secrets, policy, and artifact flow.
- Project VM contains one repo, tenant, or other security domain.
- Agent containers inside the VM isolate individual runs, branches, or tasks.

## 2. Problem Statement

AI agents need to run many commands in parallel:

- dependency installers
- build and test pipelines
- generated scripts
- shell commands from prompts

Those commands are often semi-untrusted from the host's point of view. A
plain container boundary is not strong enough when the goal is to protect the
host and neighboring projects from compromise. A VM boundary is stronger, but
VMs alone are too expensive for per-agent fan-out. fastenv combines both.

A second threat is orthogonal to boundary strength: an agent steered by
hostile content it ingests — a dependency's install script, a fetched web
page, a poisoned file in the repository — can wield its legitimate authority
against unintended targets without ever escaping its sandbox. Containment does
not address this; only limiting the authority an agent holds in the first place
does.

## 3. Product Principles

- The project boundary is the VM boundary.
- The agent boundary is the container boundary.
- eBPF is a dual-layer policy and audit plane: host eBPF protects the
  Firecracker boundary, and guest eBPF observes and constrains agents inside
  the VM.
- The host control plane never executes project code directly.
- Secrets must be short-lived, scoped, and brokered.
- Writable sharing across tenants is prohibited.
- Agents hold only the authority their task requires; the host is the sole
  source of that authority, and agents may narrow but never widen what they
  were granted.

## 4. Functional Requirements

### 4.1 Project Isolation

Each project gets one Firecracker microVM as its durable isolation boundary.
The project boundary should be chosen at the smallest trust domain that the
operator is willing to let share a guest kernel and project-local caches.

### 4.2 Agent Isolation

Inside each project VM, fastenv must be able to launch multiple `crun`
containers. Each container represents an agent run, branch, test job, or
similar unit of work.

### 4.3 Workspace Isolation

Each agent container must have its own workspace, temp area, and process tree.
Writes from one agent must not corrupt another agent's workspace or runtime
state.

### 4.4 Controlled Output Flow

Project work must leave the VM only through validated outputs such as:

- patches
- logs
- test artifacts
- build artifacts

The host should not need live access to the guest's internal workspace layout.

### 4.5 Policy and Observability

Host eBPF must run in the host kernel and observe the Firecracker/jailer
boundary plus the VM's host-side resources. Guest eBPF may run in the guest
kernel and observe agent behavior inside the VM for auditing, debugging, and
local policy enforcement.

### 4.6 Network and Secrets

Network policy must be hierarchical:

- host decides whether a VM gets network access at all
- project VM decides project-level access policy
- agent container may further restrict access for a particular run

Secrets must not be ambient — they must not be baked into base images, mounted
from host directories, or delivered as environment variables readable by the
agent process. They must be brokered: scoped to the requesting agent, redeemed
at point of use, and expired after use.

### 4.7 Syscall Surface Policy

The operator must be able to define a baseline syscall-surface policy that
applies to every guest VM and every agent container, as a hardening layer that
narrows what semi-untrusted code can ask of the kernel. This policy must be
configurable at three levels, and each level may only further restrict the level
above it, never relax it:

- a host baseline applied to every guest VM and agent container
- a project-level policy that may tighten the baseline for one project
- a per-agent policy that may tighten it further for a single run

This surface-narrowing layer is defense-in-depth around the VM and container
boundaries; it is not itself the isolation boundary (see Non-Goals).

### 4.8 Authority Model

Agent containers must start with zero ambient authority: no ambient filesystem
reach beyond their assigned workspace, and no ability to open network
connections directly. All access to resources outside the workspace must be
granted explicitly by the host, scoped to the current task, and expressible as
a minimal set of permissions the agent may further narrow but never widen when
delegating to tools or subprocesses it spawns.

## 5. Performance Expectations

- Agent sandbox creation inside a live project VM should remain fast enough
  for interactive agent loops.
- Project VM provisioning may be slower than container startup and may be
  handled by prewarming or reuse within the same trust domain.
- The system should preserve cheap fan-out for multiple concurrent agents once
  the project VM exists.

## 6. Non-Goals

- Running project code directly on the host
- Treating host containers as the security boundary for untrusted projects
- Shared writable caches across tenants
- Mounting host credentials or `~/.ssh` into agent environments
- Using eBPF as the primary isolation boundary
- Collapsing host and guest eBPF into a single policy layer
- One giant VM shared by all projects

## 7. Success Criteria

- A compromised project must not be able to compromise the host or another
  tenant through the supported execution path.
- Multiple agents can run concurrently inside the same project VM without
  stomping on each other's workspaces.
- The host can recover patches and artifacts without trusting live guest file
  system exposure.
- The architecture stays explicit about which layer owns each security
  boundary.
- Host and guest eBPF policy remain separate and kernel-local to their
  respective layers.
- An agent steered by hostile content to act against the host's interests can
  only affect resources it was explicitly granted for its task; ambient
  filesystem reach, direct network access, and secrets are not available for
  it to abuse.
