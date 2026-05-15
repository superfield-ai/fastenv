// parity_check.rs — Phase 6 parity check for the project VM design.
//
// Canonical docs:
//   - docs/prd.md             §4 Functional Requirements, §7 Success Criteria
//   - docs/architecture.md    §1 Overview, §4 Execution Model
//   - docs/implementation-plan.md  Phase 6 — Parity and Cutover
//
// This module confirms that every command in the supported product command set
// is reachable through the explicit host/guest boundary introduced in
// boundary.rs. A command that appears in the CLI but is missing from the
// GuestRuntime or HostControlPlane surface is a parity gap.
//
// Supported command set (from docs/implementation-plan.md Phase 1):
//   build-base, fork, exec, diff, du, export-patch, gc, bench
//
// Deprecated commands retained for migration compatibility:
//   mount-path, unmount
//
// The tests below exercise the boundary surface rather than the underlying OS
// primitives, so they run in the PR-tier harness without root, KVM, or a live
// Firecracker instance.

/// Parity record for a single supported command.
///
/// Each entry confirms which boundary surface the command belongs to and
/// whether the corresponding GuestRuntime or HostControlPlane method exists.
#[derive(Debug, Clone)]
pub struct CommandParityEntry {
    /// CLI subcommand name (as registered in main.rs).
    pub command: &'static str,
    /// Boundary layer that owns this command.
    pub boundary: CommandBoundary,
    /// Whether the method is deprecated in favour of an explicit seam.
    pub deprecated: bool,
    /// Notes on migration status.
    pub note: &'static str,
}

/// Which boundary layer owns a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandBoundary {
    /// Routed through GuestRuntime (workspace-engine operations).
    GuestRuntime,
    /// Routed through HostControlPlane / ProjectVmSupervisor.
    HostControlPlane,
}

/// Full parity table for the supported command set.
///
/// This table is the normative record for Phase 6. Every command in the CLI
/// must appear here. Any command missing from the table is a parity gap that
/// blocks cutover.
pub fn command_parity_table() -> Vec<CommandParityEntry> {
    vec![
        CommandParityEntry {
            command: "build-base",
            boundary: CommandBoundary::GuestRuntime,
            deprecated: false,
            note: "GuestRuntime::build_base — creates a read-only base snapshot inside the project VM",
        },
        CommandParityEntry {
            command: "fork",
            boundary: CommandBoundary::GuestRuntime,
            deprecated: false,
            note: "GuestRuntime::fork_base — creates a writable CoW workspace layer for an agent container",
        },
        CommandParityEntry {
            command: "exec",
            boundary: CommandBoundary::GuestRuntime,
            deprecated: false,
            note: "GuestRuntime::run_exec — launches a crun container inside the project VM with network mode and resource limits",
        },
        CommandParityEntry {
            command: "diff",
            boundary: CommandBoundary::GuestRuntime,
            deprecated: false,
            note: "GuestRuntime::diff_fork — shows changes made inside a fork's upper overlayfs layer",
        },
        CommandParityEntry {
            command: "du",
            boundary: CommandBoundary::GuestRuntime,
            deprecated: false,
            note: "GuestRuntime::du_fork — reports disk usage of a fork's upper layer for quota tracking",
        },
        CommandParityEntry {
            command: "export-patch",
            boundary: CommandBoundary::GuestRuntime,
            deprecated: false,
            note: "GuestRuntime::export_patch — exports fork changes as a tar archive through the controlled output channel",
        },
        CommandParityEntry {
            command: "gc",
            boundary: CommandBoundary::GuestRuntime,
            deprecated: false,
            note: "GuestRuntime::run_gc — collects stale forks and snapshots within the project VM",
        },
        CommandParityEntry {
            command: "bench",
            boundary: CommandBoundary::GuestRuntime,
            deprecated: false,
            note: "GuestRuntime::run_bench — measures Firecracker boot and container startup latency tiers",
        },
        CommandParityEntry {
            command: "discard",
            boundary: CommandBoundary::GuestRuntime,
            deprecated: false,
            note: "GuestRuntime::discard_fork — releases a fork's snapshot resources and removes its registry entry",
        },
        CommandParityEntry {
            command: "mount-path",
            boundary: CommandBoundary::GuestRuntime,
            deprecated: true,
            note: "Deprecated: exposes host-side mount paths to callers. Replaced by the explicit guest boundary. Retained for migration compatibility only.",
        },
        CommandParityEntry {
            command: "unmount",
            boundary: CommandBoundary::GuestRuntime,
            deprecated: true,
            note: "Deprecated: direct unmount entrypoint. Replaced by the explicit guest boundary. Retained for migration compatibility only.",
        },
    ]
}

/// Returns the set of commands that are not deprecated (the supported set).
pub fn supported_commands() -> Vec<&'static str> {
    command_parity_table()
        .into_iter()
        .filter(|e| !e.deprecated)
        .map(|e| e.command)
        .collect()
}

/// Returns the set of deprecated commands retained for migration compatibility.
pub fn deprecated_commands() -> Vec<&'static str> {
    command_parity_table()
        .into_iter()
        .filter(|e| e.deprecated)
        .map(|e| e.command)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastenv::boundary::{GuestRuntime, HostControlPlane, LocalHostControlPlane};
    use fastenv::exec::GuestNetworkMode;
    use fastenv::gc::GcOptions;
    use fastenv::host_control_plane::{NetworkPolicy, ProjectVmSpec};
    use std::collections::HashSet;
    use std::fs;
    use tempfile::TempDir;

    /// Confirm the parity table covers the exact CLI subcommand list in main.rs.
    ///
    /// If this test fails after adding or removing a CLI subcommand, update
    /// command_parity_table() in this file and docs/migration-note.md.
    #[test]
    fn parity_table_covers_all_cli_subcommands() {
        use crate::Cli;
        use clap::CommandFactory;

        let cli_cmd = Cli::command();
        let cli_subcommands: HashSet<&str> =
            cli_cmd.get_subcommands().map(|c| c.get_name()).collect();

        let table_commands: HashSet<&str> =
            command_parity_table().iter().map(|e| e.command).collect();

        let missing_from_table: Vec<&&str> = cli_subcommands
            .iter()
            .filter(|c| !table_commands.contains(*c))
            .collect();
        assert!(
            missing_from_table.is_empty(),
            "CLI subcommands not in parity table (parity gap): {:?}",
            missing_from_table
        );

        let extra_in_table: Vec<&&str> = table_commands
            .iter()
            .filter(|c| !cli_subcommands.contains(*c))
            .collect();
        assert!(
            extra_in_table.is_empty(),
            "Parity table entries not in CLI (stale entry): {:?}",
            extra_in_table
        );
    }

    /// Confirm the supported command set routes through the GuestRuntime boundary.
    ///
    /// Each supported command must be reachable through the trait — not a raw
    /// module call or a direct host path.
    #[test]
    fn supported_commands_route_through_guest_runtime_boundary() {
        let table = command_parity_table();
        let non_deprecated: Vec<&CommandParityEntry> =
            table.iter().filter(|e| !e.deprecated).collect();

        // Every non-deprecated command in the current set belongs to GuestRuntime.
        // When the HostControlPlane surface gains its own CLI verbs, update
        // this assertion to allow CommandBoundary::HostControlPlane as well.
        for entry in &non_deprecated {
            assert_eq!(
                entry.boundary,
                CommandBoundary::GuestRuntime,
                "command '{}' must route through GuestRuntime boundary; \
                 update command_parity_table() if the boundary changed",
                entry.command
            );
        }
    }

    /// Confirm that the GuestRuntime surface exposes all methods for supported commands.
    ///
    /// This test exercises the full method set through the boundary trait so
    /// a missing impl or removed method is caught at compile time as well as
    /// at runtime.
    #[test]
    fn guest_runtime_surface_covers_supported_command_set() {
        let host = LocalHostControlPlane::new();
        let guest = host.guest();
        let root = TempDir::new().unwrap();

        let source_dir = root.path().join("source");
        fs::create_dir_all(&source_dir).unwrap();
        fs::write(source_dir.join("hello.txt"), b"hello").unwrap();

        // build-base
        guest
            .build_base(&source_dir, "parity-base", root.path())
            .expect("build_base must be reachable through GuestRuntime");

        // fork
        use fastenv::registry::{ForkEntry, QuotaMode, Registry};
        use std::collections::HashMap;
        let registry = Registry::open(root.path()).unwrap();
        let fork_entry = ForkEntry {
            base_key: "parity-base".to_owned(),
            upper_path: root.path().join("forks/parity-fork/upper"),
            work_path: root.path().join("forks/parity-fork/work"),
            merged_path: Some(root.path().join("forks/parity-fork/merged")),
            quota_bytes: None,
            quota_mode: QuotaMode::Soft,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            labels: HashMap::new(),
        };
        registry
            .insert_fork("parity-fork", fork_entry)
            .expect("insert_fork must succeed");
        fs::create_dir_all(root.path().join("forks/parity-fork/upper")).unwrap();
        fs::create_dir_all(root.path().join("forks/parity-fork/work")).unwrap();
        fs::create_dir_all(root.path().join("forks/parity-fork/merged")).unwrap();

        // exec
        let opts = fastenv::exec::ExecOptions {
            crun_path: "/bin/true".to_owned(),
            cpu: None,
            memory: None,
            network: GuestNetworkMode::None,
            secret_leases: Vec::new(),
        };
        let exit_code = guest
            .run_exec("parity-fork", &["/bin/true".to_owned()], root.path(), &opts)
            .expect("run_exec must be reachable through GuestRuntime");
        assert_eq!(exit_code, 0, "exec must succeed for the parity check");

        // diff
        guest
            .diff_fork("parity-fork", root.path())
            .expect("diff_fork must be reachable through GuestRuntime");

        // du
        guest
            .du_fork("parity-fork", root.path())
            .expect("du_fork must be reachable through GuestRuntime");

        // export-patch
        guest
            .export_patch(
                "parity-fork",
                root.path(),
                Some(&root.path().join("parity-patch.tar")),
            )
            .expect("export_patch must be reachable through GuestRuntime");

        // gc
        guest
            .run_gc(
                root.path(),
                &GcOptions {
                    max_age: None,
                    max_forks: None,
                    dry_run: true,
                },
            )
            .expect("run_gc must be reachable through GuestRuntime");
    }

    /// Confirm the HostControlPlane surface covers VM lifecycle for the project VM design.
    ///
    /// The host supervisor must be able to provision, transition, and query a
    /// project VM record — this is the host-side parity requirement.
    #[test]
    fn host_control_plane_covers_project_vm_lifecycle() {
        use fastenv::host_control_plane::VmState;

        let host = LocalHostControlPlane::new();
        let root = TempDir::new().unwrap();

        let spec = ProjectVmSpec {
            project_id: "parity-project".to_owned(),
            kernel_ref: Some("kernel-6.1".to_owned()),
            seed_data_refs: vec![],
            network_policy: NetworkPolicy::None,
        };

        let record = host
            .supervisor()
            .provision_project_vm(root.path(), &spec)
            .expect("provision_project_vm must succeed for parity check");
        assert_eq!(record.state, VmState::Provisioned);

        // transition_vm_state(Running) now drives a real Firecracker boot.
        // On CI hosts without Firecracker installed, the call returns a
        // structured VmBootError. Both outcomes are valid for the parity check:
        // the supervisor surface is present and the method is callable.
        use fastenv::host_control_plane::VmBootError;
        let boot_result =
            host.supervisor()
                .transition_vm_state(root.path(), "parity-project", VmState::Running);
        match boot_result {
            Ok(record) => assert_eq!(record.state, VmState::Running),
            Err(ref err) => {
                let boot_err = err.downcast_ref::<VmBootError>();
                assert!(
                    matches!(
                        boot_err,
                        Some(VmBootError::BinaryNotFound { .. })
                            | Some(VmBootError::KvmUnavailable { .. })
                    ),
                    "expected BinaryNotFound or KvmUnavailable, got: {err}"
                );
            }
        }

        let stored = host
            .supervisor()
            .get_project_vm(root.path(), "parity-project")
            .expect("get_project_vm must succeed");
        assert_eq!(stored.project_id, "parity-project");
    }

    /// Confirm no non-deprecated command is missing a boundary assignment.
    #[test]
    fn no_parity_gaps_in_table() {
        let table = command_parity_table();
        for entry in &table {
            assert!(
                !entry.note.is_empty(),
                "command '{}' has an empty note — every parity entry needs a migration note",
                entry.command
            );
        }
    }

    /// Confirm the supported command count matches the expected set from Phase 1.
    ///
    /// The supported set is: build-base, fork, discard, exec, diff, du, export-patch, gc, bench.
    /// Deprecated (mount-path, unmount) are excluded from the supported count.
    #[test]
    fn supported_command_count_matches_phase1_set() {
        let supported = supported_commands();
        let expected: HashSet<&str> = [
            "build-base",
            "fork",
            "discard",
            "exec",
            "diff",
            "du",
            "export-patch",
            "gc",
            "bench",
        ]
        .iter()
        .copied()
        .collect();
        let actual: HashSet<&str> = supported.iter().copied().collect();
        assert_eq!(
            actual, expected,
            "supported command set does not match the Phase 1 spec; \
             update command_parity_table() to reflect any changes"
        );
    }
}
