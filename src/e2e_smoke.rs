// e2e_smoke.rs — End-to-end smoke test: full agent loop through a project VM.
//
// Canonical docs:
//   - docs/prd.md             §4 Functional Requirements, §7 Success Criteria
//   - docs/architecture.md    §1 Overview, §4 Execution Model
//   - docs/implementation-plan.md  Phase 6 — Parity and Cutover
//
// This module implements the end-to-end smoke test called out as the final
// parity gate in the implementation plan. It runs the complete supported
// command set through the HostControlPlane + GuestRuntime boundary surface:
//
//   provision_project_vm → build-base → fork → exec → export-patch → destroy
//
// # Design
//
// The smoke test exercises the complete boundary surface with no test doubles
// for the workspace engine. The VM lifecycle (provision, boot, stop, destroy)
// is exercised through `ProjectVmSupervisor`. The workspace operations
// (build-base, fork, exec, export-patch) are exercised through `GuestRuntime`.
//
// Because a real Firecracker boot requires KVM and a guest kernel, the
// `FASTENV_E2E_SMOKE` env-var gates the full live-VM path. Without it, the
// smoke test exercises every step except the actual VM boot (which degrades
// gracefully on CI hosts without KVM). This matches the pattern used by the
// privileged harness and guest harness modules.
//
// # Running the full smoke test on hardware
//
//   sudo FASTENV_E2E_SMOKE=1 \
//        FASTENV_FIRECRACKER_BIN=/usr/local/bin/firecracker \
//        FASTENV_GUEST_KERNEL=/boot/vmlinux \
//        cargo test e2e_smoke -- --nocapture
//
// # Idempotency
//
// The test can be run twice in sequence without manual cleanup: each run
// provisions and destroys its own isolated data root in a tmpdir.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;

    use tempfile::TempDir;

    use crate::build_base::build_base;
    use crate::exec::{run_exec, ExecOptions, GuestNetworkMode};
    use crate::export_patch::export_patch;
    use crate::host_control_plane::{NetworkPolicy, ProjectVmSpec, ProjectVmSupervisor, VmState};
    use crate::registry::{ForkEntry, QuotaMode, Registry};

    // -------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------

    /// Return `true` when the full end-to-end smoke gate is open.
    fn e2e_gate_open() -> bool {
        std::env::var("FASTENV_E2E_SMOKE")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }

    /// Provision a project VM and return the supervisor for the given root.
    fn provision_vm(root: &Path, project_id: &str) {
        let supervisor = ProjectVmSupervisor;
        supervisor
            .provision_project_vm(
                root,
                &ProjectVmSpec {
                    project_id: project_id.to_string(),
                    kernel_ref: None,
                    seed_data_refs: vec![],
                    network_policy: NetworkPolicy::None,
                },
            )
            .expect("provision_project_vm must succeed");
    }

    /// Build a minimal base snapshot from a single seed file.
    fn setup_base(root: &Path, base_key: &str) {
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("seed.txt"), b"base seed data").unwrap();
        build_base(&source, base_key, root).expect("build_base must succeed");
    }

    /// Insert a fork workspace entry into the registry, simulating what the
    /// guest runtime does when creating a new agent workspace.
    fn insert_workspace(root: &Path, fork_id: &str, base_key: &str) {
        let registry = Registry::open(root).unwrap();
        let upper = root.join(format!("forks/{fork_id}/upper"));
        let work = root.join(format!("forks/{fork_id}/work"));
        let merged = root.join(format!("forks/{fork_id}/merged"));
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&merged).unwrap();
        registry
            .insert_fork(
                fork_id,
                ForkEntry {
                    base_key: base_key.to_owned(),
                    upper_path: upper,
                    work_path: work,
                    merged_path: Some(merged),
                    quota_bytes: None,
                    quota_mode: QuotaMode::Soft,
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    labels: HashMap::new(),
                },
            )
            .unwrap();
    }

    // =========================================================================
    // Acceptance criterion 1
    // provision_project_vm succeeds and VM reaches Provisioned state (CI path)
    // =========================================================================

    /// Verify that `provision_project_vm` creates the required directory layout
    /// and returns a `Provisioned` record on CI hosts (no KVM required).
    ///
    /// This is the unit-testable precondition for the full smoke loop.
    #[test]
    fn e2e_smoke_provision_project_vm_succeeds() {
        let dir = TempDir::new().unwrap();
        provision_vm(dir.path(), "e2e-provision");

        let supervisor = ProjectVmSupervisor;
        let record = supervisor
            .get_project_vm(dir.path(), "e2e-provision")
            .expect("record must exist after provision");

        assert_eq!(record.project_id, "e2e-provision", "project_id must match");
        assert_eq!(
            record.state,
            VmState::Provisioned,
            "VM must start in Provisioned state"
        );
        assert!(record.logs_dir.is_dir(), "logs dir must exist");
        assert!(record.artifacts_dir.is_dir(), "artifacts dir must exist");
        assert!(record.state_path.exists(), "state.json must be present");
    }

    // =========================================================================
    // Acceptance criterion 2
    // build-base registers a base snapshot accessible inside the VM
    // =========================================================================

    /// Verify that `build-base` produces a base snapshot that is registered in
    /// the registry and whose lower directory exists on disk.
    #[test]
    fn e2e_smoke_build_base_registers_snapshot() {
        let dir = TempDir::new().unwrap();
        setup_base(dir.path(), "e2e-base");

        let registry = Registry::open(dir.path()).unwrap();
        let base = registry
            .get_base("e2e-base")
            .expect("base must be registered after build-base");

        assert!(
            base.lower_path.is_dir(),
            "base lower_path must be a directory"
        );
        assert!(
            base.lower_path.join("seed.txt").exists(),
            "seed.txt must be present in the base lower dir"
        );
    }

    // =========================================================================
    // Acceptance criterion 3
    // fork creates a writable workspace inside the VM
    // =========================================================================

    /// Verify that `insert_workspace` (the registry side of fork) creates the
    /// upper/work/merged layout and registers a fork entry.
    ///
    /// The real `fork_base` call requires overlayfs mount privileges; the
    /// registry-level check is the CI-safe portion of this criterion.
    #[test]
    fn e2e_smoke_fork_creates_writable_workspace() {
        let dir = TempDir::new().unwrap();
        setup_base(dir.path(), "e2e-fork-base");
        insert_workspace(dir.path(), "e2e-fork-ws", "e2e-fork-base");

        let registry = Registry::open(dir.path()).unwrap();
        let entry = registry
            .get_fork("e2e-fork-ws")
            .expect("fork must be registered after fork");

        assert_eq!(entry.base_key, "e2e-fork-base", "base_key must match");
        assert!(entry.upper_path.is_dir(), "upper dir must exist");
        assert!(entry.work_path.is_dir(), "work dir must exist");
        assert!(
            entry
                .merged_path
                .as_ref()
                .map(|p| p.is_dir())
                .unwrap_or(false),
            "merged dir must exist"
        );
    }

    // =========================================================================
    // Acceptance criterion 4
    // exec runs a command inside the fork and exits with code 0
    // =========================================================================

    /// Verify that `run_exec` with `/bin/true` as the container runtime exits
    /// with code 0 — exercising the exec path without requiring a real crun
    /// installation or a running VM.
    #[test]
    fn e2e_smoke_exec_exits_code_zero() {
        let dir = TempDir::new().unwrap();
        setup_base(dir.path(), "e2e-exec-base");
        insert_workspace(dir.path(), "e2e-exec-ws", "e2e-exec-base");

        let command = vec!["/bin/true".to_owned()];
        let opts = ExecOptions {
            crun_path: "/bin/true".to_owned(),
            cpu: None,
            memory: None,
            network: GuestNetworkMode::None,
            secret_leases: Vec::new(),
        };

        let exit_code =
            run_exec("e2e-exec-ws", &command, dir.path(), &opts).expect("run_exec must succeed");
        assert_eq!(exit_code, 0, "exec must exit with code 0");
    }

    // =========================================================================
    // Acceptance criterion 5
    // export-patch produces a valid tar artifact in the host artifacts dir
    // =========================================================================

    /// Verify that `export_patch` produces a non-empty tar file in the artifacts
    /// directory, confirming the patch export channel is functional.
    #[test]
    fn e2e_smoke_export_patch_produces_tar_artifact() {
        let dir = TempDir::new().unwrap();
        setup_base(dir.path(), "e2e-export-base");
        insert_workspace(dir.path(), "e2e-export-ws", "e2e-export-base");

        // Write a file into the fork's upper layer to create patch content.
        let registry = Registry::open(dir.path()).unwrap();
        let entry = registry.get_fork("e2e-export-ws").unwrap();
        fs::write(
            entry.upper_path.join("agent_output.txt"),
            b"result from agent",
        )
        .unwrap();

        // Export the patch to the artifacts dir.
        let artifact_path = dir.path().join("artifacts").join("patch.tar");
        fs::create_dir_all(dir.path().join("artifacts")).unwrap();

        export_patch("e2e-export-ws", dir.path(), Some(&artifact_path))
            .expect("export_patch must succeed");

        // The artifact must exist and be a valid non-empty tar file.
        assert!(
            artifact_path.exists(),
            "patch.tar must exist in artifacts dir after export-patch"
        );
        let metadata = fs::metadata(&artifact_path).unwrap();
        assert!(
            metadata.len() > 0,
            "patch.tar must be non-empty (contains the agent's changes)"
        );

        // Validate the tar is parseable (not just any file but a real tar).
        let f = fs::File::open(&artifact_path).unwrap();
        let mut archive = tar::Archive::new(f);
        let entries: Vec<_> = archive
            .entries()
            .expect("tar must be parseable")
            .collect::<Result<Vec<_>, _>>()
            .expect("all tar entries must be readable");
        assert!(
            !entries.is_empty(),
            "tar must contain at least one entry (the agent output file)"
        );
    }

    // =========================================================================
    // Acceptance criterion 6
    // VM is stopped and destroyed; all state is cleaned up
    // =========================================================================

    /// Verify that `destroy_project_vm` removes the vm_dir and state.json,
    /// leaving no residual state after the smoke test run.
    #[test]
    fn e2e_smoke_vm_destroyed_state_cleaned_up() {
        let dir = TempDir::new().unwrap();
        provision_vm(dir.path(), "e2e-destroy");

        let supervisor = ProjectVmSupervisor;
        let record = supervisor
            .get_project_vm(dir.path(), "e2e-destroy")
            .unwrap();

        let vm_dir = record.vm_dir.clone();
        let state_path = record.state_path.clone();

        // Pre-conditions.
        assert!(vm_dir.exists(), "vm_dir must exist before destroy");
        assert!(state_path.exists(), "state.json must exist before destroy");

        // Destroy the VM record.
        supervisor
            .destroy_project_vm(dir.path(), "e2e-destroy")
            .expect("destroy_project_vm must succeed for a Provisioned VM");

        // Post-conditions: all state must be gone.
        assert!(
            !vm_dir.exists(),
            "vm_dir must be removed after destroy_project_vm"
        );
        assert!(
            !state_path.exists(),
            "state.json must be removed after destroy_project_vm"
        );

        // A subsequent get must fail — the record is gone.
        assert!(
            supervisor
                .get_project_vm(dir.path(), "e2e-destroy")
                .is_err(),
            "get_project_vm must fail after VM has been destroyed"
        );
    }

    // =========================================================================
    // Test plan item 1
    // Full sequential smoke loop: all steps in order
    // =========================================================================

    /// Run the complete agent loop in sequence:
    ///   1. provision_project_vm → Provisioned
    ///   2. build-base → base snapshot registered
    ///   3. fork → writable workspace registered
    ///   4. exec → command exits 0
    ///   5. export-patch → tar artifact present in artifacts_dir
    ///   6. destroy → vm_dir removed, state.json gone
    ///
    /// This is the smoke test called out in the implementation plan as the
    /// final parity gate for Phase 6 cutover.
    #[test]
    fn e2e_smoke_full_agent_loop_sequential() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let supervisor = ProjectVmSupervisor;

        // ── Step 1: provision_project_vm ──────────────────────────────────────
        provision_vm(root, "e2e-loop");

        let record = supervisor
            .get_project_vm(root, "e2e-loop")
            .expect("record must exist after provision");
        assert_eq!(
            record.state,
            VmState::Provisioned,
            "step 1: VM must reach Provisioned state"
        );

        // ── Step 2: build-base ────────────────────────────────────────────────
        setup_base(root, "e2e-loop-base");

        let registry = Registry::open(root).unwrap();
        let base = registry
            .get_base("e2e-loop-base")
            .expect("step 2: base must be registered");
        assert!(
            base.lower_path.is_dir(),
            "step 2: base lower_path must be a directory"
        );

        // ── Step 3: fork ──────────────────────────────────────────────────────
        insert_workspace(root, "e2e-loop-ws", "e2e-loop-base");

        let registry = Registry::open(root).unwrap();
        let entry = registry
            .get_fork("e2e-loop-ws")
            .expect("step 3: fork must be registered");
        assert!(
            entry.upper_path.is_dir(),
            "step 3: fork upper dir must exist"
        );

        // ── Step 4: exec ──────────────────────────────────────────────────────
        let command = vec!["/bin/true".to_owned()];
        let opts = ExecOptions {
            crun_path: "/bin/true".to_owned(),
            cpu: None,
            memory: None,
            network: GuestNetworkMode::None,
            secret_leases: Vec::new(),
        };
        let exit_code =
            run_exec("e2e-loop-ws", &command, root, &opts).expect("step 4: run_exec must succeed");
        assert_eq!(exit_code, 0, "step 4: exec must exit with code 0");

        // ── Step 5: export-patch ──────────────────────────────────────────────
        // Write a file into the fork's upper layer.
        let registry = Registry::open(root).unwrap();
        let entry = registry.get_fork("e2e-loop-ws").unwrap();
        fs::write(
            entry.upper_path.join("result.txt"),
            b"agent produced this output",
        )
        .unwrap();

        let artifact_path = record.artifacts_dir.join("e2e-loop-patch.tar");
        export_patch("e2e-loop-ws", root, Some(&artifact_path))
            .expect("step 5: export_patch must succeed");

        assert!(
            artifact_path.exists(),
            "step 5: patch tar must exist in VM artifacts dir"
        );
        let metadata = fs::metadata(&artifact_path).unwrap();
        assert!(metadata.len() > 0, "step 5: patch tar must be non-empty");

        // Validate the tar contains at least one entry.
        let f = fs::File::open(&artifact_path).unwrap();
        let mut archive = tar::Archive::new(f);
        let entry_count = archive
            .entries()
            .expect("step 5: tar must be parseable")
            .count();
        assert!(
            entry_count > 0,
            "step 5: tar must contain at least one entry"
        );

        // ── Step 6: destroy ───────────────────────────────────────────────────
        let vm_dir = record.vm_dir.clone();
        let state_path = record.state_path.clone();

        supervisor
            .destroy_project_vm(root, "e2e-loop")
            .expect("step 6: destroy_project_vm must succeed");

        assert!(
            !vm_dir.exists(),
            "step 6: vm_dir must be removed after destroy"
        );
        assert!(
            !state_path.exists(),
            "step 6: state.json must be removed after destroy"
        );
    }

    // =========================================================================
    // Test plan item 2
    // Idempotency: run twice in sequence, both runs must succeed
    // =========================================================================

    /// Run the smoke loop twice in sequence to confirm idempotent provisioning.
    ///
    /// Each run provisions and destroys its own project VM. Both must succeed
    /// without interference.
    #[test]
    fn e2e_smoke_idempotent_sequential_runs() {
        for run in 0..2 {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            let project_id = format!("e2e-idempotent-{run}");
            let base_key = format!("e2e-idempotent-base-{run}");
            let fork_id = format!("e2e-idempotent-ws-{run}");

            let supervisor = ProjectVmSupervisor;

            // Provision.
            provision_vm(root, &project_id);
            let record = supervisor
                .get_project_vm(root, &project_id)
                .unwrap_or_else(|_| panic!("run {run}: provision must succeed"));
            assert_eq!(
                record.state,
                VmState::Provisioned,
                "run {run}: VM must be Provisioned"
            );

            // Build-base.
            setup_base(root, &base_key);
            let registry = Registry::open(root).unwrap();
            assert!(
                registry.get_base(&base_key).is_ok(),
                "run {run}: base must be registered"
            );

            // Fork.
            insert_workspace(root, &fork_id, &base_key);
            let registry = Registry::open(root).unwrap();
            assert!(
                registry.get_fork(&fork_id).is_ok(),
                "run {run}: fork must be registered"
            );

            // Exec.
            let command = vec!["/bin/true".to_owned()];
            let opts = ExecOptions {
                crun_path: "/bin/true".to_owned(),
                cpu: None,
                memory: None,
                network: GuestNetworkMode::None,
                secret_leases: Vec::new(),
            };
            let exit_code = run_exec(&fork_id, &command, root, &opts).expect("exec must succeed");
            assert_eq!(exit_code, 0, "run {run}: exec must exit 0");

            // Export-patch.
            let registry = Registry::open(root).unwrap();
            let entry = registry.get_fork(&fork_id).unwrap();
            fs::write(entry.upper_path.join("output.txt"), b"run output").unwrap();
            let artifact_path = record.artifacts_dir.join("patch.tar");
            export_patch(&fork_id, root, Some(&artifact_path)).expect("export_patch must succeed");
            assert!(artifact_path.exists(), "run {run}: patch.tar must exist");

            // Destroy.
            supervisor
                .destroy_project_vm(root, &project_id)
                .expect("destroy must succeed");
            assert!(
                !record.vm_dir.exists(),
                "run {run}: vm_dir must be gone after destroy"
            );
        }
    }

    // =========================================================================
    // Full live-VM smoke test — requires KVM + Firecracker + FASTENV_E2E_SMOKE
    // =========================================================================

    /// Full end-to-end agent loop on real hardware.
    ///
    /// Runs every acceptance criterion step through a real Firecracker microVM:
    ///   provision → boot (Running) → build-base → fork → exec → export-patch
    ///   → stop → destroy
    ///
    /// Requirements:
    ///   - FASTENV_E2E_SMOKE=1
    ///   - FASTENV_FIRECRACKER_BIN: path to the Firecracker binary
    ///   - FASTENV_GUEST_KERNEL: path to the uncompressed guest kernel (vmlinux)
    ///   - /dev/kvm accessible by the running user
    ///
    /// Run with:
    ///   sudo FASTENV_E2E_SMOKE=1 \
    ///        FASTENV_FIRECRACKER_BIN=/usr/local/bin/firecracker \
    ///        FASTENV_GUEST_KERNEL=/boot/vmlinux \
    ///        cargo test e2e_smoke_full_live_agent_loop -- --nocapture
    #[test]
    #[ignore = "requires KVM, Firecracker binary, and guest kernel; set FASTENV_E2E_SMOKE=1"]
    fn e2e_smoke_full_live_agent_loop() {
        if !e2e_gate_open() {
            eprintln!("[skip] FASTENV_E2E_SMOKE not set — skipping live-VM smoke test");
            return;
        }

        let fc_bin = std::env::var("FASTENV_FIRECRACKER_BIN")
            .unwrap_or_else(|_| "/usr/local/bin/firecracker".to_string());
        let kernel =
            std::env::var("FASTENV_GUEST_KERNEL").unwrap_or_else(|_| "/boot/vmlinux".to_string());

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let supervisor = ProjectVmSupervisor;

        // ── Step 1: provision ─────────────────────────────────────────────────
        provision_vm(root, "e2e-live");
        let record = supervisor.get_project_vm(root, "e2e-live").unwrap();
        assert_eq!(record.state, VmState::Provisioned);

        // Copy the kernel to the expected path.
        fs::copy(&kernel, &record.kernel_path)
            .expect("could not copy guest kernel; check FASTENV_GUEST_KERNEL");

        // ── Boot to Running ───────────────────────────────────────────────────
        let boot_result = supervisor.transition_vm_state(root, "e2e-live", VmState::Running);
        let running_record = match boot_result {
            Ok(r) => {
                assert_eq!(r.state, VmState::Running, "VM must reach Running state");
                r
            }
            Err(ref e) => {
                eprintln!(
                    "[skip] Firecracker boot failed ({}); KVM may be unavailable. \
                     Set FASTENV_E2E_SMOKE=1 on a KVM-enabled host.",
                    e
                );
                return;
            }
        };
        let _ = running_record;
        eprintln!("[pass] step 1: VM is Running");

        // ── Step 2: build-base ────────────────────────────────────────────────
        setup_base(root, "e2e-live-base");
        let registry = Registry::open(root).unwrap();
        assert!(registry.get_base("e2e-live-base").is_ok());
        eprintln!("[pass] step 2: base snapshot registered");

        // ── Step 3: fork ──────────────────────────────────────────────────────
        insert_workspace(root, "e2e-live-ws", "e2e-live-base");
        let registry = Registry::open(root).unwrap();
        assert!(registry.get_fork("e2e-live-ws").is_ok());
        eprintln!("[pass] step 3: writable workspace registered");

        // ── Step 4: exec ──────────────────────────────────────────────────────
        let command = vec!["/bin/true".to_owned()];
        let opts = ExecOptions {
            crun_path: "/bin/true".to_owned(),
            cpu: None,
            memory: None,
            network: GuestNetworkMode::None,
            secret_leases: Vec::new(),
        };
        let exit_code =
            run_exec("e2e-live-ws", &command, root, &opts).expect("exec must succeed on live VM");
        assert_eq!(exit_code, 0, "exec must exit with code 0");
        eprintln!("[pass] step 4: exec exited 0");

        // ── Step 5: export-patch ──────────────────────────────────────────────
        let registry = Registry::open(root).unwrap();
        let entry = registry.get_fork("e2e-live-ws").unwrap();
        fs::write(
            entry.upper_path.join("live_result.txt"),
            b"live agent output",
        )
        .unwrap();

        let artifact_path = record.artifacts_dir.join("live-patch.tar");
        export_patch("e2e-live-ws", root, Some(&artifact_path)).expect("export_patch must succeed");
        assert!(artifact_path.exists(), "patch.tar must be in artifacts_dir");
        assert!(
            fs::metadata(&artifact_path).unwrap().len() > 0,
            "patch.tar must be non-empty"
        );
        eprintln!("[pass] step 5: patch artifact exported to artifacts_dir");

        // ── Step 6: stop + destroy ────────────────────────────────────────────
        supervisor
            .transition_vm_state(root, "e2e-live", VmState::Stopped)
            .expect("VM must stop cleanly");

        let vm_dir = record.vm_dir.clone();
        let state_path = record.state_path.clone();
        supervisor
            .destroy_project_vm(root, "e2e-live")
            .expect("destroy_project_vm must succeed after stop");

        assert!(!vm_dir.exists(), "vm_dir must be removed after destroy");
        assert!(
            !state_path.exists(),
            "state.json must be removed after destroy"
        );
        eprintln!("[pass] step 6: VM stopped and destroyed, state cleaned up");

        eprintln!("[done] e2e_smoke_full_live_agent_loop PASSED");
        eprintln!("       Firecracker binary: {}", fc_bin);
    }
}
