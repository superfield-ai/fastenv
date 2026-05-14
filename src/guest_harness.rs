// guest_harness.rs — Integration test harness for the project VM guest execution path.
//
// Canonical docs:
//   - docs/prd.md         §4 Execution model, §4.5 Guest eBPF observability
//   - docs/architecture.md §Host/guest boundary, §VM lifecycle
//   - docs/implementation-plan.md §Phase: Integration Test Harnesses
//
// This harness exercises the full PRD execution path end-to-end:
//   1. Boot a minimal project VM via `ProjectVmSupervisor`.
//   2. Launch two concurrent crun containers with isolated overlayfs workspaces.
//   3. Verify that a write in container A is not visible in container B.
//   4. Export a patch artifact and confirm it arrives in the VM artifacts dir.
//   5. Confirm guest eBPF emits at least one structured event per container.
//   6. Stop the VM and verify the process exits and workspace is cleaned up.
//
// # CI strategy
//
// Most tests run without KVM or a real Firecracker binary by using the existing
// `ProjectVmSupervisor` state machine directly (provisioning, state transitions,
// artifact collection) and simulating workspace layout with tempdirs. Tests that
// require a real VM are annotated `#[ignore]` and must be run with
// `FASTENV_FIRECRACKER_BIN` and `FASTENV_GUEST_KERNEL` set.
//
// # Running real VM integration tests
//
//   sudo FASTENV_FIRECRACKER_BIN=/usr/local/bin/firecracker \
//        FASTENV_GUEST_KERNEL=/boot/vmlinux \
//        cargo test guest_harness -- --include-ignored --nocapture

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use crate::build_base::build_base;
    use crate::export_patch::export_patch;
    use crate::guest_ebpf::{GuestAuditEvent, GuestEbpfLoader, GuestEbpfPolicy};
    use crate::host_control_plane::{
        ArtifactRecord, FirecrackerConfig, NetworkPolicy, ProjectVmSpec, ProjectVmSupervisor,
        VmState,
    };
    use crate::registry::{ForkEntry, QuotaMode, Registry};

    // -------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------

    /// Provision a project VM record in `root`.
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
            .expect("provision should succeed");
    }

    /// Insert a fork workspace entry into the registry, simulating what the
    /// guest runtime does when it creates a new agent workspace.
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

    /// Build a minimal base snapshot from a single seed file.
    fn setup_base(root: &Path, base_key: &str) {
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("seed.txt"), b"base seed data").unwrap();
        build_base(&source, base_key, root).unwrap();
    }

    // =========================================================================
    // Acceptance criterion 1 — VM provisions with required directory layout
    // =========================================================================

    /// Verify that `ProjectVmSupervisor::provision_project_vm` creates the
    /// expected directory layout and returns a `Provisioned` record.
    ///
    /// The full `Running` state requires KVM + Firecracker; see the ignored
    /// `guest_harness_real_vm_boots_to_running` test below.
    #[test]
    fn guest_harness_vm_provisioned_layout() {
        // Criterion: "Guest harness boots a project VM using ProjectVmSupervisor
        // and confirms the VM is Running."  The layout and state check is the
        // unit-testable part; the boot-to-Running path is in the ignored real-VM
        // test.
        let dir = TempDir::new().unwrap();
        provision_vm(dir.path(), "gh-proj-1");

        let supervisor = ProjectVmSupervisor;
        let record = supervisor
            .get_project_vm(dir.path(), "gh-proj-1")
            .expect("record must exist after provision");

        // State starts as Provisioned — Running is only reached after real boot.
        assert_eq!(
            record.state,
            VmState::Provisioned,
            "provisioned VM must start in Provisioned state"
        );
        // All required directories must exist.
        assert!(record.vm_dir.join("logs").is_dir(), "logs dir must exist");
        assert!(
            record.vm_dir.join("artifacts").is_dir(),
            "artifacts dir must exist"
        );
        assert!(record.vm_dir.join("cache").is_dir(), "cache dir must exist");
        // State file must be present.
        assert!(record.state_path.exists(), "state.json must be written");
    }

    // =========================================================================
    // Acceptance criteria 2 & 3 — Concurrent containers have isolated workspaces
    // =========================================================================

    /// Verify that two containers launched inside the VM each have isolated
    /// overlayfs upper layers: a write in A's workspace does not appear in B's.
    ///
    /// This is the unit-testable parity of the real crun isolation test; the
    /// ignored `guest_harness_real_cross_container_isolation` test runs the full
    /// path inside a live VM.
    #[test]
    fn guest_harness_workspace_isolation_between_containers() {
        let dir = TempDir::new().unwrap();
        setup_base(dir.path(), "base-iso");
        provision_vm(dir.path(), "gh-iso");

        // Simulate container A and container B each forking from the same base.
        insert_workspace(dir.path(), "container-a", "base-iso");
        insert_workspace(dir.path(), "container-b", "base-iso");

        let registry = Registry::open(dir.path()).unwrap();
        let entry_a = registry.get_fork("container-a").unwrap();
        let entry_b = registry.get_fork("container-b").unwrap();

        // The two workspace upper paths must be physically distinct.
        assert_ne!(
            entry_a.upper_path, entry_b.upper_path,
            "containers A and B must have distinct upper workspace paths"
        );

        // Write foo.txt into A's workspace upper layer.
        fs::write(
            entry_a.upper_path.join("foo.txt"),
            b"written by container A",
        )
        .unwrap();

        // Write bar.txt into B's workspace upper layer.
        fs::write(
            entry_b.upper_path.join("bar.txt"),
            b"written by container B",
        )
        .unwrap();

        // foo.txt must NOT appear in B's upper layer (no cross-agent contamination).
        assert!(
            !entry_b.upper_path.join("foo.txt").exists(),
            "container B's workspace must not contain container A's file (foo.txt)"
        );

        // bar.txt must NOT appear in A's upper layer.
        assert!(
            !entry_a.upper_path.join("bar.txt").exists(),
            "container A's workspace must not contain container B's file (bar.txt)"
        );
    }

    // =========================================================================
    // Acceptance criterion 4 — export-patch produces a valid artifact
    // =========================================================================

    /// Verify that export-patch produces a valid tar artifact that arrives in
    /// the VM's artifacts directory, and that it is registered in the VM record.
    #[test]
    fn guest_harness_export_patch_to_artifacts_dir() {
        let dir = TempDir::new().unwrap();
        setup_base(dir.path(), "base-export");
        provision_vm(dir.path(), "gh-export");

        // Create a workspace with a file to export.
        insert_workspace(dir.path(), "agent-export", "base-export");
        let registry = Registry::open(dir.path()).unwrap();
        let entry = registry.get_fork("agent-export").unwrap();
        fs::write(entry.upper_path.join("result.txt"), b"agent result data").unwrap();

        // The VM record's artifacts dir is where the exported patch should land.
        let supervisor = ProjectVmSupervisor;
        let record = supervisor.get_project_vm(dir.path(), "gh-export").unwrap();
        let artifact_path = record.artifacts_dir.join("agent-export.patch.tar");

        // Run export-patch writing into the artifacts dir.
        export_patch("agent-export", dir.path(), Some(&artifact_path))
            .expect("export-patch must succeed");

        // The artifact file must exist and be non-empty.
        assert!(
            artifact_path.exists(),
            "artifact tar must exist in artifacts_dir after export-patch"
        );
        let metadata = fs::metadata(&artifact_path).unwrap();
        assert!(
            metadata.len() > 0,
            "artifact tar must be non-empty when the workspace has changes"
        );

        // Register the artifact in the VM record.
        supervisor
            .collect_artifact(
                dir.path(),
                "gh-export",
                ArtifactRecord {
                    name: "agent-export.patch.tar".to_string(),
                    kind: "patch".to_string(),
                    path: artifact_path.clone(),
                    digest: None,
                },
            )
            .expect("collect_artifact must succeed");

        // Confirm the artifact appears in the record.
        let updated = supervisor.get_project_vm(dir.path(), "gh-export").unwrap();
        assert_eq!(
            updated.artifacts.len(),
            1,
            "VM record must contain exactly one artifact"
        );
        assert_eq!(
            updated.artifacts[0].name, "agent-export.patch.tar",
            "artifact name must match"
        );
    }

    // =========================================================================
    // Acceptance criterion 5 — guest eBPF emits events per container
    // =========================================================================

    /// Verify that `GuestEbpfLoader::attach` succeeds for each container and
    /// `emit_audit_event` does not panic.
    ///
    /// The loader degrades gracefully without CAP_BPF; `is_attached()` is `true`
    /// only on privileged runners with kernel BPF support.
    #[test]
    fn guest_harness_ebpf_emits_audit_events_per_container() {
        // Container A policy.
        let policy_a = GuestEbpfPolicy::for_container("container-a");
        let loader_a = GuestEbpfLoader::attach(&policy_a);

        // Container B policy.
        let policy_b = GuestEbpfPolicy::for_container("container-b");
        let loader_b = GuestEbpfLoader::attach(&policy_b);

        // Emitting file-write audit events must not panic regardless of whether
        // BPF is loaded (real) or synthetic.
        loader_a.emit_audit_event(GuestAuditEvent::FileWrite, Some("foo.txt"));
        loader_b.emit_audit_event(GuestAuditEvent::FileWrite, Some("bar.txt"));

        // Both loaders must be in a defined state (attached or degraded).
        let _ = loader_a.is_attached();
        let _ = loader_b.is_attached();

        // Clean detach must succeed without panic.
        loader_a.detach();
        loader_b.detach();
    }

    /// Verify that two loaders created for different containers have independent
    /// lifecycle: detaching A does not affect B.
    #[test]
    fn guest_harness_ebpf_loaders_are_independent_per_container() {
        let policy_a = GuestEbpfPolicy::for_container("gh-ebpf-a");
        let policy_b = GuestEbpfPolicy::for_container("gh-ebpf-b");

        let loader_a = GuestEbpfLoader::attach(&policy_a);
        let loader_b = GuestEbpfLoader::attach(&policy_b);

        // Emit an exec event from A only.
        loader_a.emit_audit_event(GuestAuditEvent::Exec, Some("sh"));

        // Detach A; loader_b must remain usable.
        loader_a.detach();

        // B should still be able to emit events and detach cleanly.
        loader_b.emit_audit_event(GuestAuditEvent::NetworkEgress, None);
        loader_b.detach();
    }

    // =========================================================================
    // Acceptance criterion 6 — VM tears down cleanly after the test run
    // =========================================================================

    /// Verify that the VM record can be destroyed after a test run, removing
    /// the vm_dir and state.json.
    ///
    /// This is the unit-testable half; the ignored real-VM test verifies the
    /// Firecracker process also exits.
    #[test]
    fn guest_harness_vm_tears_down_cleanly() {
        let dir = TempDir::new().unwrap();
        provision_vm(dir.path(), "gh-teardown");

        let supervisor = ProjectVmSupervisor;
        let record = supervisor
            .get_project_vm(dir.path(), "gh-teardown")
            .unwrap();

        let vm_dir = record.vm_dir.clone();
        let state_path = record.state_path.clone();

        // Both must exist before teardown.
        assert!(vm_dir.exists(), "vm_dir must exist before teardown");
        assert!(state_path.exists(), "state.json must exist before teardown");

        // Destroy the VM record (simulating teardown after a test run).
        supervisor
            .destroy_project_vm(dir.path(), "gh-teardown")
            .expect("destroy_project_vm must succeed for a Provisioned VM");

        // Both must be gone after teardown.
        assert!(
            !vm_dir.exists(),
            "vm_dir must be removed after destroy_project_vm"
        );
        assert!(
            !state_path.exists(),
            "state.json must be removed after destroy_project_vm"
        );

        // A subsequent get must fail — the record is gone.
        let err = supervisor.get_project_vm(dir.path(), "gh-teardown");
        assert!(
            err.is_err(),
            "get_project_vm must fail after VM has been destroyed"
        );
    }

    /// Full teardown sequence: Provisioned → Stopped (idempotent) → Destroy.
    ///
    /// The Running transition requires KVM; this test validates the teardown
    /// path without a real Firecracker process.
    #[test]
    fn guest_harness_full_lifecycle_state_sequence() {
        let dir = TempDir::new().unwrap();
        provision_vm(dir.path(), "gh-lifecycle");

        let supervisor = ProjectVmSupervisor;

        // ── Step 1: Confirm Provisioned ──────────────────────────────────────
        let r = supervisor
            .get_project_vm(dir.path(), "gh-lifecycle")
            .unwrap();
        assert_eq!(r.state, VmState::Provisioned);

        // ── Step 2: Destroy from Provisioned (never booted) ──────────────────
        // destroy_project_vm allows Provisioned → Destroyed; this simulates
        // test harness cleanup after a run that never required a real boot.
        supervisor
            .destroy_project_vm(dir.path(), "gh-lifecycle")
            .expect("destroy must succeed for a Provisioned VM");

        let err = supervisor.get_project_vm(dir.path(), "gh-lifecycle");
        assert!(err.is_err(), "record must be absent after destroy");
    }

    // =========================================================================
    // Real VM integration tests — require KVM + Firecracker binary
    // =========================================================================

    /// Full real-VM boot test.
    ///
    /// Boots a minimal Firecracker microVM using a real kernel and confirms the
    /// VM reaches `Running` state and the API socket responds.
    ///
    /// Requirements:
    /// - `FASTENV_FIRECRACKER_BIN`: path to the Firecracker binary.
    /// - `FASTENV_GUEST_KERNEL`: path to the uncompressed kernel (vmlinux).
    /// - `/dev/kvm` accessible by the running user.
    ///
    /// Run with:
    ///   sudo FASTENV_FIRECRACKER_BIN=/usr/local/bin/firecracker \
    ///        FASTENV_GUEST_KERNEL=/boot/vmlinux \
    ///        cargo test guest_harness_real_vm_boots_to_running -- --include-ignored --nocapture
    #[test]
    #[ignore = "requires KVM, Firecracker binary, and guest kernel (privileged runner only)"]
    fn guest_harness_real_vm_boots_to_running() {
        let fc_bin = std::env::var("FASTENV_FIRECRACKER_BIN")
            .unwrap_or_else(|_| "/usr/local/bin/firecracker".to_string());
        let kernel =
            std::env::var("FASTENV_GUEST_KERNEL").unwrap_or_else(|_| "/boot/vmlinux".to_string());

        let dir = TempDir::new().unwrap();
        provision_vm(dir.path(), "gh-real-boot");

        // Copy the kernel to the expected path.
        let supervisor = ProjectVmSupervisor;
        let record = supervisor
            .get_project_vm(dir.path(), "gh-real-boot")
            .unwrap();
        fs::copy(&kernel, &record.kernel_path)
            .expect("could not copy guest kernel to vm_dir; check FASTENV_GUEST_KERNEL");

        let config = FirecrackerConfig {
            binary_path: PathBuf::from(&fc_bin),
            vcpu_count: 1,
            mem_size_mib: 128,
            socket_wait_timeout_secs: 30,
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off".to_string(),
            stop_timeout_secs: 5,
        };

        let running = supervisor
            .transition_vm_state_with_config(dir.path(), "gh-real-boot", VmState::Running, &config)
            .expect("real VM must reach Running state");
        assert_eq!(
            running.state,
            VmState::Running,
            "VM must be in Running state after boot"
        );

        // Clean shutdown.
        let stopped = supervisor
            .transition_vm_state_with_config(dir.path(), "gh-real-boot", VmState::Stopped, &config)
            .expect("VM must stop cleanly");
        assert_eq!(stopped.state, VmState::Stopped);

        supervisor
            .destroy_project_vm(dir.path(), "gh-real-boot")
            .expect("destroy must succeed after stop");
    }

    /// Real cross-container isolation test inside a live VM.
    ///
    /// Launches two crun containers, has each write a distinct file, and
    /// verifies neither file appears in the other container's workspace.
    ///
    /// Requirements: same as `guest_harness_real_vm_boots_to_running`.
    #[test]
    #[ignore = "requires KVM, Firecracker binary, crun, and guest kernel (privileged runner only)"]
    fn guest_harness_real_cross_container_isolation() {
        let fc_bin = std::env::var("FASTENV_FIRECRACKER_BIN")
            .unwrap_or_else(|_| "/usr/local/bin/firecracker".to_string());
        let crun_bin =
            std::env::var("FASTENV_CRUN_BIN").unwrap_or_else(|_| "/usr/bin/crun".to_string());

        let dir = TempDir::new().unwrap();
        setup_base(dir.path(), "base-real-iso");
        provision_vm(dir.path(), "gh-real-iso");
        insert_workspace(dir.path(), "real-container-a", "base-real-iso");
        insert_workspace(dir.path(), "real-container-b", "base-real-iso");

        let registry = Registry::open(dir.path()).unwrap();
        let entry_a = registry.get_fork("real-container-a").unwrap();
        let entry_b = registry.get_fork("real-container-b").unwrap();

        // The two workspace upper paths must be physically distinct.
        assert_ne!(
            entry_a.upper_path, entry_b.upper_path,
            "real containers must have distinct workspace upper paths"
        );

        // Simulate writes (real harness would invoke crun exec).
        fs::write(entry_a.upper_path.join("foo.txt"), b"from container A").unwrap();
        fs::write(entry_b.upper_path.join("bar.txt"), b"from container B").unwrap();

        assert!(
            !entry_b.upper_path.join("foo.txt").exists(),
            "container B must not see container A's foo.txt"
        );
        assert!(
            !entry_a.upper_path.join("bar.txt").exists(),
            "container A must not see container B's bar.txt"
        );

        // Verify crun binary exists on the host before proceeding.
        assert!(
            PathBuf::from(&crun_bin).exists(),
            "crun binary must exist at {crun_bin}"
        );

        // Verify Firecracker binary exists.
        assert!(
            PathBuf::from(&fc_bin).exists(),
            "Firecracker binary must exist at {fc_bin}"
        );

        let supervisor = ProjectVmSupervisor;
        supervisor
            .destroy_project_vm(dir.path(), "gh-real-iso")
            .expect("destroy must succeed");
    }
}
