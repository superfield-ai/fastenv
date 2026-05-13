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
    export_patch, fork, gc, mount_path,
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

    fn guest(&self) -> &Self::Guest;
}

/// Default host-control-plane wrapper around the current runtime.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalHostControlPlane {
    guest: LocalGuestRuntime,
}

impl LocalHostControlPlane {
    pub fn new() -> Self {
        Self::default()
    }
}

impl HostControlPlane for LocalHostControlPlane {
    type Guest = LocalGuestRuntime;

    fn guest(&self) -> &Self::Guest {
        &self.guest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

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
            network: Some("host".to_owned()),
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
}
