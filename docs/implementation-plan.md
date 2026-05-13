# fastenv Project VM Refactor Plan

> This plan replaces the old containerd-era rewrite plan. It assumes the
> product and architecture are now anchored on:
> - [docs/prd.md](docs/prd.md)
> - [docs/architecture.md](docs/architecture.md)

## Goal

Refactor fastenv into a two-layer system:

- Host control plane that manages Firecracker microVMs, policy, secrets,
  artifacts, and host-kernel eBPF.
- Guest runtime that runs `crun` containers inside each project VM and uses
  guest-kernel eBPF for audit and policy.

The implementation must stop treating host containers or direct host
overlayfs mounts as the product boundary.

## What to Rip Out

These pieces are legacy host-side mechanics from the containerd/overlayfs
design and should be removed or fully retired once the replacement path is in
place:

- Containerd client, snapshotter, shim, and gRPC assumptions.
- Host-mounted writable workspace exposure for untrusted projects.
- CLI and library paths that imply `containerdSocket`, `containerdNamespace`,
  or `--snapshotter` are part of the product contract.
- Host-side exec flows that assume the host kernel directly runs project
  commands.
- Any branch of the code that treats the host overlayfs mount as the durable
  project boundary.
- The Go prototype surface once the Rust and VM-backed replacements reach
  parity for the supported product behaviors.
- Concrete legacy areas to remove or retire:
  - `cmd/root.go`, `cmd/fork.go`, `cmd/exec.go`, `cmd/gc.go`, `cmd/diff.go`,
    `cmd/mount_path.go`, and related containerd-oriented command glue.
  - `internal/execer`, `internal/gcer`, `internal/snapshotter`,
    `internal/mounter`, `internal/cachemanager`, and
    `internal/testutil/containerd.go`.
  - Any Rust module or helper that still assumes the host overlayfs tree is
    the final project boundary instead of a guest-runtime primitive.

## What to Refactor and Reuse

These pieces are salvageable, but their ownership changes:

- Workspace primitives such as `build-base`, `diff`, `du`, and
  `export-patch` become guest-runtime utilities instead of host boundaries.
- Registry and quota logic become project-local storage management inside the
  VM, not the host trust boundary.
- Benchmarks become tiered harnesses that measure both host VM lifecycle and
  guest sandbox startup.
- Logging and CLI structure stay, but the command semantics must map to the
  host/guest split described in the architecture doc.
- The Rust implementation should become the canonical code path for the new
  architecture; the Go tree is legacy once parity is complete.

## Phase 1 - Carve the Boundary

Goal: freeze the current behavior with tests, then introduce explicit host and
guest interfaces before deleting the old implicit ones.

- [ ] Add a host/guest boundary layer in code and docs so the current
      workspace-engine logic can be called as a guest primitive.
      The explicit seam lives in `src/boundary.rs`.
- [ ] Add a regression suite that records the current behavior of
      `build-base`, `fork`, `exec`, `diff`, `du`, `export-patch`, `gc`, and
      `bench`.
- [ ] Split current code paths into "host control plane candidate" and
      "guest runtime candidate" modules.
- [ ] Mark every remaining containerd-specific entrypoint as deprecated in the
      CLI and library surfaces.

## Phase 2 - Build the Host Control Plane

Goal: provision and govern project microVMs without project code executing on
the host.

- [ ] Firecracker supervisor and VM lifecycle manager.
- [ ] Per-project VM registry and state store.
- [ ] Host-side image and cache manager for kernels, base images, and read-only
      seed data.
- [ ] Secret broker with short-lived scoped injection.
- [ ] Artifact collector and patch validator.
- [ ] Host-network attachment and egress policy manager.
- [ ] Host eBPF policy loader for the Firecracker/jailer boundary.

## Phase 3 - Build the Guest Runtime

Goal: run agent work inside the project VM with cheap fan-out and strict
in-VM isolation.

- [ ] Guest agent supervisor that launches `crun` containers.
- [ ] Guest-local overlayfs workspace manager for per-agent workspaces.
- [ ] Guest-local quota enforcement and cache layout.
- [ ] Guest eBPF policy loader for agent behavior inside the VM.
- [ ] Guest-to-host artifact export channel for patches, logs, and build
      outputs.
- [ ] Explicit network modes inside the VM: none, package-mirror-only,
      allowlist, and audited egress.

## Phase 4 - Remove the Legacy Host Path

Goal: delete the old implementation once the host/guest split is complete and
covered by tests.

- [ ] Remove containerd client, snapshotter, shim, and gRPC code paths.
- [ ] Remove host-mounted writable workspace code paths.
- [ ] Remove CLI flags and config options that encode the old host snapshotter
      model.
- [ ] Delete or archive the Go prototype after Rust parity is complete.
- [ ] Remove compatibility tests that only exist to protect legacy host
      behavior.

## Phase 5 - Add the Right Test Harnesses

Goal: make the new architecture testable at the correct boundary layers.

### PR-tier harness

- [ ] Pure unit tests for registry, path handling, quota parsing, policy
      plumbing, and artifact serialization.
- [ ] No root, no KVM, no Firecracker, no guest boot.

### Privileged host harness

- [ ] Overlayfs and mount tests on a privileged Linux runner.
- [ ] Firecracker boot smoke tests on bare metal or equivalent KVM-enabled
      hardware.
- [ ] Host eBPF policy tests that verify the Firecracker/jailer boundary and
      tap/network controls.

### Guest harness

- [ ] Boot a minimal project VM image and execute a containerized workload
      inside it.
- [ ] Verify guest overlayfs workspace behavior, per-agent isolation, and
      guest eBPF policy decisions.
- [ ] Validate guest-to-host artifact export and secret injection paths.

### Security regression harness

- [ ] Unauthorized file-write attempts outside the workspace are blocked.
- [ ] Unauthorized network egress attempts are blocked or logged according to
      policy.
- [ ] Cross-agent contamination is prevented inside one project VM.
- [ ] Host-level policy still holds when the guest workload is malicious.

### Benchmark harness

- [ ] Measure Firecracker boot time.
- [ ] Measure agent container startup time inside a live VM.
- [ ] Measure host eBPF overhead separately from guest eBPF overhead.
- [ ] Measure patch export, artifact export, and workspace diff latency.

## Phase 6 - Parity and Cutover

Goal: switch the canonical product path to the new architecture only after it
is proven equivalent or better on the supported scenarios.

- [ ] Confirm the new host/guest split covers the current supported command
      set.
- [ ] Confirm the new harnesses pass on the intended execution hardware.
- [ ] Confirm the old implementation can be removed without losing supported
      behavior.
- [ ] Publish the migration note for operators and contributors.

## Notes on Sequencing

- Do not delete the legacy host path until Phase 3 and Phase 5 are both
  passing.
- Do not treat guest-runtime code as host-safe until the VM boundary and host
  eBPF policy are exercised in integration tests.
- Do not optimize for latency before the host/guest split is observable in
  tests.
- Keep the CLI surface stable where possible; change semantics behind the
  same commands before introducing new commands.
