// boundary.rs — explicit host/guest interfaces for the current runtime.
//
// Canonical docs:
//   - docs/prd.md
//   - docs/architecture.md
//   - docs/implementation-plan.md
//
// This module does not change product behavior. It makes the current runtime
// surface explicit so the host control plane and the guest runtime candidate
// can be referenced independently in code and tests while the refactor is in
// flight.

use std::path::Path;

use anyhow::Result;

use crate::{
    bench::{self, BenchOptions, BenchResult},
    build_base, diff, discard, du,
    exec::{self, ExecOptions},
    export_patch, fork, gc,
    host_control_plane::ProjectVmSupervisor,
    mount_path,
};

/// Guest-runtime boundary for the current workspace engine.
///
/// The host control plane should only call into the guest-facing operations
/// through this trait while the split is being carved out.
pub trait GuestRuntime {
    fn build_base(&self, source_dir: &Path, base_key: &str, root: &Path) -> Result<()>;
    fn fork_base(
        &self,
        base_key: &str,
        fork_key: &str,
        root: &Path,
        quota_bytes: Option<u64>,
    ) -> Result<()>;
    fn discard_fork(&self, fork_key: &str, root: &Path) -> Result<()>;
    fn run_exec(
        &self,
        fork_key: &str,
        command: &[String],
        root: &Path,
        opts: &ExecOptions,
    ) -> Result<i32>;
    fn diff_fork(&self, fork_key: &str, root: &Path) -> Result<()>;
    fn du_fork(&self, fork_key: &str, root: &Path) -> Result<()>;
    fn export_patch(&self, fork_key: &str, root: &Path, output_path: Option<&Path>) -> Result<()>;
    fn run_gc(&self, root: &Path, opts: &gc::GcOptions) -> Result<()>;
    fn mount_path(&self, fork_key: &str, root: &Path) -> Result<()>;
    fn unmount_fork(&self, fork_key: &str, root: &Path) -> Result<()>;
    fn run_bench(&self, base_key: &str, root: &Path, opts: &BenchOptions) -> Result<BenchResult>;
}

/// Default guest-runtime implementation backed by the current modules.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalGuestRuntime;

impl GuestRuntime for LocalGuestRuntime {
    fn build_base(&self, source_dir: &Path, base_key: &str, root: &Path) -> Result<()> {
        build_base::build_base(source_dir, base_key, root)
    }

    fn fork_base(
        &self,
        base_key: &str,
        fork_key: &str,
        root: &Path,
        quota_bytes: Option<u64>,
    ) -> Result<()> {
        fork::fork_base(base_key, fork_key, root, quota_bytes)
    }

    fn discard_fork(&self, fork_key: &str, root: &Path) -> Result<()> {
        discard::discard_fork(fork_key, root)
    }

    fn run_exec(
        &self,
        fork_key: &str,
        command: &[String],
        root: &Path,
        opts: &ExecOptions,
    ) -> Result<i32> {
        exec::run_exec(fork_key, command, root, opts)
    }

    fn diff_fork(&self, fork_key: &str, root: &Path) -> Result<()> {
        diff::diff_fork(fork_key, root)
    }

    fn du_fork(&self, fork_key: &str, root: &Path) -> Result<()> {
        du::du_fork(fork_key, root)
    }

    fn export_patch(&self, fork_key: &str, root: &Path, output_path: Option<&Path>) -> Result<()> {
        export_patch::export_patch(fork_key, root, output_path)
    }

    fn run_gc(&self, root: &Path, opts: &gc::GcOptions) -> Result<()> {
        gc::run_gc(root, opts)
    }

    fn mount_path(&self, fork_key: &str, root: &Path) -> Result<()> {
        #[allow(deprecated)]
        mount_path::mount_path(fork_key, root)
    }

    fn unmount_fork(&self, fork_key: &str, root: &Path) -> Result<()> {
        #[allow(deprecated)]
        mount_path::unmount_fork(fork_key, root)
    }

    fn run_bench(&self, base_key: &str, root: &Path, opts: &BenchOptions) -> Result<BenchResult> {
        bench::run_bench(base_key, root, opts)
    }
}

/// Host-control-plane boundary for the current runtime.
///
/// The host owns orchestration, while the guest runtime candidate owns the
/// workspace-engine operations. For now the host simply exposes the guest
/// primitive explicitly.
pub trait HostControlPlane {
    type Guest: GuestRuntime;
    type Supervisor;

    fn guest(&self) -> &Self::Guest;
    fn supervisor(&self) -> &Self::Supervisor;
}

/// Default host-control-plane wrapper around the current runtime.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalHostControlPlane {
    guest: LocalGuestRuntime,
    supervisor: ProjectVmSupervisor,
}

impl LocalHostControlPlane {
    pub fn new() -> Self {
        Self::default()
    }
}

impl HostControlPlane for LocalHostControlPlane {
    type Guest = LocalGuestRuntime;
    type Supervisor = ProjectVmSupervisor;

    fn guest(&self) -> &Self::Guest {
        &self.guest
    }

    fn supervisor(&self) -> &Self::Supervisor {
        &self.supervisor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    use crate::exec::GuestNetworkMode;
    use crate::host_control_plane::{
        ArtifactRecord, NetworkPolicy, ProjectVmSpec, SecretLease, VmBootError, VmState,
    };
    use crate::registry::{ForkEntry, QuotaMode, Registry};

    fn make_fork_entry(
        base_key: &str,
        upper: std::path::PathBuf,
        work: std::path::PathBuf,
        merged_path: Option<std::path::PathBuf>,
    ) -> ForkEntry {
        ForkEntry {
            base_key: base_key.to_owned(),
            upper_path: upper,
            work_path: work,
            merged_path,
            quota_bytes: None,
            quota_mode: QuotaMode::Soft,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            labels: HashMap::new(),
        }
    }

    #[test]
    fn host_exposes_guest_boundary() {
        let host = LocalHostControlPlane::new();
        let guest = host.guest();
        let root = TempDir::new().unwrap();

        let source_dir = root.path().join("source");
        fs::create_dir_all(&source_dir).unwrap();
        fs::write(source_dir.join("hello.txt"), b"hello").unwrap();

        guest
            .build_base(&source_dir, "base-1", root.path())
            .unwrap();

        let registry = Registry::open(root.path()).unwrap();
        registry
            .insert_fork(
                "fork-1",
                make_fork_entry(
                    "base-1",
                    root.path().join("forks/fork-1/upper"),
                    root.path().join("forks/fork-1/work"),
                    Some(root.path().join("forks/fork-1/merged")),
                ),
            )
            .unwrap();
        fs::create_dir_all(root.path().join("forks/fork-1/upper")).unwrap();
        fs::create_dir_all(root.path().join("forks/fork-1/work")).unwrap();
        fs::create_dir_all(root.path().join("forks/fork-1/merged")).unwrap();

        let command = vec!["/bin/true".to_owned()];
        let opts = ExecOptions {
            crun_path: "/bin/true".to_owned(),
            cpu: None,
            memory: None,
            network: GuestNetworkMode::Host,
            secret_leases: Vec::new(),
        };

        let exit_code = guest
            .run_exec("fork-1", &command, root.path(), &opts)
            .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn guest_boundary_surface_is_complete() {
        let host = LocalHostControlPlane::new();
        let guest = host.guest();
        let root = TempDir::new().unwrap();
        let source_dir = root.path().join("source");
        fs::create_dir_all(&source_dir).unwrap();
        fs::write(source_dir.join("hello.txt"), b"hello").unwrap();

        guest
            .build_base(&source_dir, "base-1", root.path())
            .unwrap();

        let registry = Registry::open(root.path()).unwrap();
        registry
            .insert_fork(
                "fork-1",
                make_fork_entry(
                    "base-1",
                    root.path().join("forks/fork-1/upper"),
                    root.path().join("forks/fork-1/work"),
                    Some(root.path().join("forks/fork-1/merged")),
                ),
            )
            .unwrap();
        fs::create_dir_all(root.path().join("forks/fork-1/upper")).unwrap();
        fs::create_dir_all(root.path().join("forks/fork-1/work")).unwrap();
        fs::create_dir_all(root.path().join("forks/fork-1/merged")).unwrap();

        guest.diff_fork("fork-1", root.path()).unwrap();
        guest.du_fork("fork-1", root.path()).unwrap();
        guest
            .export_patch("fork-1", root.path(), Some(&root.path().join("patch.tar")))
            .unwrap();
        guest
            .run_gc(
                root.path(),
                &gc::GcOptions {
                    max_age: Some(std::time::Duration::from_secs(0)),
                    max_forks: None,
                    dry_run: true,
                },
            )
            .unwrap();
    }

    #[test]
    fn host_control_plane_provisions_and_tracks_vm_state() {
        let host = LocalHostControlPlane::new();
        let root = TempDir::new().unwrap();

        let record = host
            .supervisor()
            .provision_project_vm(
                root.path(),
                &ProjectVmSpec {
                    project_id: "project-1".to_owned(),
                    kernel_ref: Some("kernel-6.1".to_owned()),
                    seed_data_refs: vec!["seed-ro".to_owned()],
                    network_policy: NetworkPolicy::Allowlist {
                        hosts: vec!["mirror.local".to_owned()],
                    },
                },
            )
            .unwrap();

        assert_eq!(record.project_id, "project-1");
        assert_eq!(record.state, VmState::Provisioned);
        assert!(record.vm_dir.ends_with("vms/project-1"));
        assert!(record.state_path.exists());
        assert!(record.logs_dir.is_dir());
        assert!(record.artifacts_dir.is_dir());
        assert!(record.kernel_path.exists());
        assert!(record.rootfs_path.exists());
        assert!(record.workspace_path.exists());

        // transition_vm_state(Running) now drives a real Firecracker boot.
        // On a development host without Firecracker installed, the call must
        // return a structured VmBootError rather than silently writing state.
        let boot_result =
            host.supervisor()
                .transition_vm_state(root.path(), "project-1", VmState::Running);
        match boot_result {
            Ok(record) => {
                // Firecracker was available and booted successfully.
                assert_eq!(record.state, VmState::Running);
                host.supervisor()
                    .transition_vm_state(root.path(), "project-1", VmState::Stopped)
                    .expect("stopping a running VM should succeed");
            }
            Err(ref err) => {
                // Firecracker binary is absent or KVM is unavailable — both are
                // valid structured errors on CI hosts without Firecracker.
                let boot_err = err.downcast_ref::<VmBootError>();
                assert!(
                    matches!(
                        boot_err,
                        Some(VmBootError::BinaryNotFound { .. })
                            | Some(VmBootError::KvmUnavailable { .. })
                    ),
                    "expected BinaryNotFound or KvmUnavailable, got: {:?}",
                    boot_err
                );
            }
        }

        // Secret injection, artifact collection, and eBPF policy attachment do
        // not require the VM to be in Running state — they operate on the
        // on-disk record regardless of lifecycle state.
        let record = host
            .supervisor()
            .attach_network_policy(
                root.path(),
                "project-1",
                NetworkPolicy::PackageMirrorOnly {
                    mirror: Some("https://mirror.local".to_owned()),
                },
            )
            .unwrap();
        assert!(matches!(
            record.network_policy,
            NetworkPolicy::PackageMirrorOnly { .. }
        ));

        let record = host
            .supervisor()
            .inject_secret(
                root.path(),
                "project-1",
                SecretLease {
                    secret_name: "npm-token".to_owned(),
                    scope: "project".to_owned(),
                    expires_at: "2026-01-01T00:00:00Z".to_owned(),
                    secret_value: "npm_secret_token_value".to_owned(),
                },
            )
            .unwrap();
        assert_eq!(record.secrets.len(), 1);

        let record = host
            .supervisor()
            .collect_artifact(
                root.path(),
                "project-1",
                ArtifactRecord {
                    name: "patch.tar".to_owned(),
                    kind: "patch".to_owned(),
                    path: root.path().join("vms/project-1/artifacts/patch.tar"),
                    digest: Some("sha256:abc".to_owned()),
                },
            )
            .unwrap();
        assert_eq!(record.artifacts.len(), 1);

        // Note: load_host_ebpf_policy now performs a real bpf(2) syscall to
        // load the program into the host kernel. It requires CAP_BPF and a
        // real BPF ELF object. That integration test is in the
        // `host_ebpf_load_and_attach` integration test (privileged runner only).
        // Here we only verify the record fields set by the preceding operations.
        let stored = host
            .supervisor()
            .get_project_vm(root.path(), "project-1")
            .unwrap();
        // The VM may be Provisioned (no Firecracker on this host) or Stopped
        // (if boot succeeded and was shut down). It must not be Running.
        assert_ne!(stored.state, VmState::Running);
        assert_eq!(stored.secrets.len(), 1);
        assert_eq!(stored.artifacts.len(), 1);
        // eBPF policy is None until load_host_ebpf_policy is called on a
        // privileged runner with a real BPF object file.
        assert!(stored.host_ebpf_policy.is_none());
    }

    #[test]
    fn guest_runtime_can_launch_multiple_containers() {
        let host = LocalHostControlPlane::new();
        let guest = *host.guest();
        let root = TempDir::new().unwrap();
        let root_path = root.path().to_path_buf();
        let source_dir = root_path.join("source");
        fs::create_dir_all(&source_dir).unwrap();
        fs::write(source_dir.join("hello.txt"), b"hello").unwrap();

        guest
            .build_base(&source_dir, "base-1", root_path.as_path())
            .unwrap();

        let registry = Registry::open(root_path.as_path()).unwrap();
        for fork_id in ["fork-a", "fork-b"] {
            registry
                .insert_fork(
                    fork_id,
                    make_fork_entry(
                        "base-1",
                        root_path.join(format!("forks/{fork_id}/upper")),
                        root_path.join(format!("forks/{fork_id}/work")),
                        Some(root_path.join(format!("forks/{fork_id}/merged"))),
                    ),
                )
                .unwrap();
            fs::create_dir_all(root_path.join(format!("forks/{fork_id}/upper"))).unwrap();
            fs::create_dir_all(root_path.join(format!("forks/{fork_id}/work"))).unwrap();
            fs::create_dir_all(root_path.join(format!("forks/{fork_id}/merged"))).unwrap();
        }

        let mut handles = Vec::new();
        for (fork_id, network) in [
            ("fork-a", GuestNetworkMode::None),
            ("fork-b", GuestNetworkMode::AuditedEgress),
        ] {
            let guest = guest;
            let root_path = root_path.clone();
            handles.push(std::thread::spawn(move || {
                let command = vec!["/bin/true".to_owned()];
                let opts = ExecOptions {
                    crun_path: "/bin/true".to_owned(),
                    cpu: None,
                    memory: None,
                    network,
                    secret_leases: Vec::new(),
                };
                guest.run_exec(fork_id, &command, root_path.as_path(), &opts)
            }));
        }

        for handle in handles {
            assert_eq!(handle.join().unwrap().unwrap(), 0);
        }
    }
}
