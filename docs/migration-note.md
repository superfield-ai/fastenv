# Migration Note: Project VM Cutover

## Summary

This note documents the cutover from the legacy host-side execution model to
the project VM architecture described in `docs/architecture.md`. The Rust
implementation is now the canonical code path. The Go prototype is deprecated
and no longer part of the supported product surface.

## What Changed

### Architecture

The product now runs on a two-layer host/guest split:

- **Host control plane** — schedules projects, manages Firecracker microVMs,
  brokers secrets, collects artifacts, and enforces host-side eBPF policy.
- **Guest runtime** — runs `crun` containers inside each project VM, manages
  per-agent overlayfs workspaces, and applies guest-kernel eBPF policy.

The host no longer executes project code directly. Every agent run goes through
a project VM boundary.

### Boundary surface

All CLI commands now route through the explicit host/guest boundary introduced
in `src/boundary.rs`:

- `HostControlPlane` — host-side orchestration (VM lifecycle, secrets,
  artifacts, network policy, host eBPF).
- `GuestRuntime` — workspace-engine operations (build-base, fork, exec, diff,
  du, export-patch, gc, bench).

Code that called workspace modules directly should be updated to go through
`LocalHostControlPlane::new().guest()` or the `GuestRuntime` trait.

### Supported command set after cutover

The following commands are supported through the project VM design:

| Command        | Boundary     | Notes                                                        |
|----------------|--------------|--------------------------------------------------------------|
| `build-base`   | GuestRuntime | Creates a read-only base snapshot inside the project VM      |
| `fork`         | GuestRuntime | Creates a writable CoW workspace layer for an agent          |
| `discard`      | GuestRuntime | Releases a fork's snapshot resources and registry entry      |
| `exec`         | GuestRuntime | Launches a crun container with network mode and limits       |
| `diff`         | GuestRuntime | Shows changes in a fork's upper overlayfs layer              |
| `du`           | GuestRuntime | Reports disk usage of a fork's upper layer                   |
| `export-patch` | GuestRuntime | Exports fork changes as a tar archive                        |
| `gc`           | GuestRuntime | Collects stale forks and snapshots within the project VM     |
| `bench`        | GuestRuntime | Measures Firecracker boot and container startup latency      |

### Deprecated commands

The following commands are deprecated and retained only for migration
compatibility. They emit a warning log when used and will be removed in a
future release:

| Command      | Reason for deprecation                                        |
|--------------|---------------------------------------------------------------|
| `mount-path` | Exposes host-side mount paths directly; use the guest boundary |
| `unmount`    | Direct unmount entrypoint; use the guest boundary instead      |

## What Was Removed

### Go prototype

The Go prototype (`cmd/` and `internal/`) has been deprecated. The supported
product behaviors are now covered by the Rust implementation through the
explicit host/guest boundary. Operators and contributors should use the Rust
binary (`fastenv`) instead.

### Legacy host-side paths

The following legacy paths no longer form part of the product contract:

- Containerd client, snapshotter, shim, and gRPC assumptions.
- Host-mounted writable workspace exposure for untrusted projects.
- CLI flags that encoded the old host snapshotter model
  (`--containerdSocket`, `--containerdNamespace`, `--snapshotter`).
- Host-side exec flows that assumed the host kernel directly ran project
  commands.
- Any code path that treated the host overlayfs mount as the durable project
  boundary.

## Parity Verification

The `src/parity_check.rs` module provides the normative parity table and tests
that must pass before any future cutover or removal step:

- `parity_table_covers_all_cli_subcommands` — confirms the table matches the CLI exactly.
- `supported_commands_route_through_guest_runtime_boundary` — confirms every
  supported command goes through the boundary trait.
- `guest_runtime_surface_covers_supported_command_set` — exercises all methods
  through the boundary so a missing impl is caught at compile time.
- `host_control_plane_covers_project_vm_lifecycle` — confirms the host
  supervisor can provision, transition, and query a project VM.
- `no_parity_gaps_in_table` — confirms every table entry has a migration note.
- `supported_command_count_matches_phase1_set` — confirms the supported set
  matches the Phase 1 spec from `docs/implementation-plan.md`.

All six tests must pass (`cargo test parity`) before removing any legacy path
or treating the guest runtime as the canonical production surface.

## For Operators

If you are running the legacy Go-based fastenv:

1. Stop the Go binary.
2. Install the Rust binary (`cargo build --release`).
3. Replace `fastenv` invocations in your scripts. The subcommand names are
   identical for the supported set (build-base, fork, exec, diff, du,
   export-patch, gc, bench).
4. Replace any use of `mount-path` or `unmount` with the appropriate guest
   boundary call. These commands still work but emit deprecation warnings.
5. Remove any CLI flags that referenced containerd or the old snapshotter
   model — they are no longer accepted.

## For Contributors

- The canonical implementation is Rust. New features go into `src/`.
- The host/guest boundary is the primary seam. Keep host and guest operations
  on their respective sides.
- The parity table in `src/parity_check.rs` must be updated whenever a CLI
  subcommand is added or removed.
- See `docs/architecture.md` for the full trust model and invariants.
- See `docs/implementation-plan.md` Phase 6 for the remaining cutover checklist.
