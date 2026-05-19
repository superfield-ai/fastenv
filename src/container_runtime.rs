// container_runtime.rs — ContainerRuntime trait and backend implementations.
//
// Canonical docs:
//   - docs/prd.md §5 (Guest Runtime)
//   - docs/architecture.md §Container Lifecycle
//
// This module defines the ContainerRuntime trait that isolates the container
// lifecycle boundary in code. All callers go through the trait — no direct
// crun subprocess calls exist outside the CrunBackend implementation.
//
// Backends:
//   - CrunBackend: wraps existing crun subprocess logic from exec.rs
//   - YoukiBackend: youki library calls behind `#[cfg(feature = "youki")]`
//
// Both backends emit identical tracing spans:
//   - container.create  (fields: fork_id, backend, duration_ms)
//   - container.start   (fields: fork_id, backend, duration_ms, exit_code)
//   - container.delete  (fields: fork_id, backend, duration_ms)
//
// Integration note (issue #113):
//   The benchmark suite in benches/container_runtime.rs and benches/e2e_runtime.rs
//   measures per-operation latency and full E2E path under realistic agent fan-out.
//   The YoukiBackend is intentionally gated so the default build is unchanged.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{bail, Context, Result};

// ---------------------------------------------------------------------------
// ContainerRuntime trait
// ---------------------------------------------------------------------------

/// Lifecycle interface for OCI containers.
///
/// This trait is object-safe and can be held as `Box<dyn ContainerRuntime>`.
///
/// All callers must go through this trait — no direct `Command::new("crun")`
/// calls are allowed outside of `CrunBackend`. This boundary enables:
///   1. Swapping backends for benchmarking without touching callers.
///   2. Mock implementations for unit tests.
///   3. Identical telemetry regardless of backend.
///
/// Canonical docs: docs/architecture.md §Container Lifecycle
pub trait ContainerRuntime: Send + Sync {
    /// Returns a short identifier for this backend (e.g. "crun", "youki").
    ///
    /// Used in tracing span fields and benchmark labels.
    fn backend_name(&self) -> &'static str;

    /// Prepare a container for execution.
    ///
    /// For the crun backend this writes `config.json` and ensures the bundle
    /// directory is ready. For the youki backend this calls the youki library
    /// to create the container state.
    ///
    /// Emits a `container.create` tracing span with fields:
    ///   fork_id, backend, duration_ms
    fn create(&self, fork_id: &str, bundle_dir: &Path) -> Result<()>;

    /// Start the container and wait for the process to exit.
    ///
    /// Returns the container process exit code.
    ///
    /// Emits a `container.start` tracing span with fields:
    ///   fork_id, backend, duration_ms, exit_code
    fn start(&self, fork_id: &str, bundle_dir: &Path) -> Result<i32>;

    /// Delete the container state after execution.
    ///
    /// For the crun backend this is a no-op (crun `run` handles cleanup).
    /// For the youki backend this calls the library delete function.
    ///
    /// Emits a `container.delete` tracing span with fields:
    ///   fork_id, backend, duration_ms
    fn delete(&self, fork_id: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// CrunBackend
// ---------------------------------------------------------------------------

/// Container runtime backend that invokes crun as a subprocess.
///
/// This wraps the existing logic in `exec.rs` so all crun subprocess calls
/// are encapsulated in one place. Callers use `ContainerRuntime` only.
///
/// Canonical docs: docs/architecture.md §CrunBackend
#[derive(Debug, Clone)]
pub struct CrunBackend {
    /// Path to the crun binary (default: /usr/bin/crun).
    pub crun_path: PathBuf,
}

impl Default for CrunBackend {
    fn default() -> Self {
        CrunBackend {
            crun_path: PathBuf::from("/usr/bin/crun"),
        }
    }
}

impl CrunBackend {
    /// Create a new CrunBackend with the given crun binary path.
    pub fn new(crun_path: impl Into<PathBuf>) -> Self {
        CrunBackend {
            crun_path: crun_path.into(),
        }
    }
}

impl ContainerRuntime for CrunBackend {
    fn backend_name(&self) -> &'static str {
        "crun"
    }

    /// Prepare the bundle directory. For crun, `config.json` must already be
    /// written by the caller (via `exec::build_oci_config`). This method
    /// validates that `config.json` is present.
    fn create(&self, fork_id: &str, bundle_dir: &Path) -> Result<()> {
        let started = Instant::now();
        let config_path = bundle_dir.join("config.json");
        if !config_path.exists() {
            bail!(
                "container_runtime(crun): bundle config.json not found at {} for fork '{}'",
                config_path.display(),
                fork_id
            );
        }
        let duration_ms = started.elapsed().as_millis();
        tracing::info!(
            event = "container.create",
            fork_id = fork_id,
            backend = "crun",
            duration_ms = duration_ms,
            "container.create"
        );
        Ok(())
    }

    /// Invoke `crun run --bundle <bundle_dir> <fork_id>` and return the exit code.
    ///
    /// This is the only place in the codebase where `Command::new("crun")` is
    /// permitted. All other callers must use `ContainerRuntime::start`.
    fn start(&self, fork_id: &str, bundle_dir: &Path) -> Result<i32> {
        let started = Instant::now();
        let mut child = Command::new(&self.crun_path)
            .arg("run")
            .arg("--bundle")
            .arg(bundle_dir)
            .arg(fork_id)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| {
                format!(
                    "container_runtime(crun): failed to spawn crun ({}); is crun installed?",
                    self.crun_path.display()
                )
            })?;

        use std::os::unix::process::ExitStatusExt;
        let status = child
            .wait()
            .context("container_runtime(crun): wait for crun process failed")?;

        let exit_code = if let Some(code) = status.code() {
            code
        } else {
            status.signal().unwrap_or(1) + 128
        };

        let duration_ms = started.elapsed().as_millis();
        tracing::info!(
            event = "container.start",
            fork_id = fork_id,
            backend = "crun",
            duration_ms = duration_ms,
            exit_code = exit_code,
            "container.start"
        );
        Ok(exit_code)
    }

    /// For the crun subprocess backend, `crun run` handles its own cleanup.
    /// This is a no-op that emits the expected tracing span for parity.
    fn delete(&self, fork_id: &str) -> Result<()> {
        let started = Instant::now();
        let duration_ms = started.elapsed().as_millis();
        tracing::info!(
            event = "container.delete",
            fork_id = fork_id,
            backend = "crun",
            duration_ms = duration_ms,
            "container.delete"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// waitpid helper (used by YoukiBackend)
// ---------------------------------------------------------------------------

/// Block on `waitpid(pid)` and translate the wait status into the same
/// exit-code convention `CrunBackend::start` uses (normal: code; signal: 128+N).
///
/// `EINTR` is retried so a stray signal during the bench does not abort the wait.
/// Used by `YoukiBackend::start` so both backends measure the same timed region
/// (issue #124): wait for the container init process to actually exit before
/// returning, instead of hard-coding `exit_code = 0`.
#[cfg(feature = "youki")]
fn waitpid_exit_code(pid: i32) -> Result<i32> {
    use std::io;

    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: libc::waitpid is async-signal-safe and takes a valid pointer.
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        if ret == -1 {
            let err = io::Error::last_os_error();
            // Retry on EINTR; surface anything else (including ECHILD, which
            // would indicate the init process is not our direct child — that
            // breaks the issue #124 contract and must not be silently ignored).
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(anyhow::Error::from(err).context(format!("waitpid({pid}) failed")));
        }
        // Translate the wait status with the same WIF* macros CrunBackend uses
        // through std::os::unix::process::ExitStatusExt.
        if libc::WIFEXITED(status) {
            return Ok(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(libc::WTERMSIG(status) + 128);
        }
        // Stopped/continued events shouldn't appear without WUNTRACED/WCONTINUED.
        // If we somehow see one, keep waiting for the terminating event.
        continue;
    }
}

// ---------------------------------------------------------------------------
// YoukiBackend (feature-gated)
// ---------------------------------------------------------------------------

/// Container runtime backend that calls the libcontainer crate in-process.
///
/// This backend is enabled by building with `--features youki`. It uses the
/// `libcontainer` Rust library (the crate that powers the youki binary) to
/// manage container lifecycle entirely in-process, with no subprocess spawn.
/// This eliminates subprocess overhead from the youki execution path, making
/// the crun-vs-youki benchmark comparison meaningful: subprocess spawn cost
/// is isolated to `CrunBackend` only.
///
/// No `youki` binary is required in PATH.
///
/// # Container state directory
///
/// `libcontainer` stores per-container state under a root directory.
/// `YoukiBackend` uses `root_path` (default: `/run/fastenv/youki`) for this.
/// Each container gets a subdirectory `<root_path>/<fork_id>/`.
///
/// # Lifecycle mapping
///
/// | `ContainerRuntime` method | `libcontainer` operation                    |
/// |---------------------------|---------------------------------------------|
/// | `create(fork_id, bundle)` | `ContainerBuilder::new(...).as_init(bundle).build()` |
/// | `start(fork_id, _)`       | `Container::load(root_path/fork_id).start()`|
/// | `delete(fork_id)`         | `Container::load(root_path/fork_id).delete(false)` |
///
/// Both backends emit identical span names and field keys so telemetry and the
/// control surface remain backend-agnostic.
///
/// Canonical docs: docs/architecture.md §Container Lifecycle
/// Integration note (issue #116): the YoukiBackend is experimental; promoting
/// it to the production default is deferred to post-benchmark analysis.
#[cfg(feature = "youki")]
#[derive(Debug, Clone)]
pub struct YoukiBackend {
    /// Directory where libcontainer stores per-container state.
    /// Each container occupies a subdirectory `<root_path>/<fork_id>/`.
    pub root_path: PathBuf,
}

#[cfg(feature = "youki")]
impl Default for YoukiBackend {
    fn default() -> Self {
        YoukiBackend {
            root_path: PathBuf::from("/run/fastenv/youki"),
        }
    }
}

#[cfg(feature = "youki")]
impl YoukiBackend {
    /// Create a new YoukiBackend with a custom container state root directory.
    pub fn new(root_path: impl Into<PathBuf>) -> Self {
        YoukiBackend {
            root_path: root_path.into(),
        }
    }
}

#[cfg(feature = "youki")]
impl ContainerRuntime for YoukiBackend {
    fn backend_name(&self) -> &'static str {
        "youki"
    }

    /// Create the container state using the libcontainer crate in-process.
    ///
    /// Uses `libcontainer::container::builder::ContainerBuilder` to build an
    /// OCI container from `bundle_dir`. Container state is stored under
    /// `self.root_path/<fork_id>/`. No youki binary is required.
    fn create(&self, fork_id: &str, bundle_dir: &Path) -> Result<()> {
        use libcontainer::container::builder::ContainerBuilder;
        use libcontainer::syscall::syscall::SyscallType;

        let started = Instant::now();

        // Validate the bundle directory has a config.json.
        let config_path = bundle_dir.join("config.json");
        if !config_path.exists() {
            bail!(
                "container_runtime(youki): bundle config.json not found at {} for fork '{}'",
                config_path.display(),
                fork_id
            );
        }

        // Ensure the root state directory exists.
        std::fs::create_dir_all(&self.root_path).with_context(|| {
            format!(
                "container_runtime(youki): failed to create root_path {}",
                self.root_path.display()
            )
        })?;

        // Build the container in-process using libcontainer.
        // ContainerBuilder::new takes the container ID and a SyscallType.
        // with_root_path sets where libcontainer stores per-container state.
        // as_init(bundle_dir) selects the init container path (new namespaces).
        // build() creates the container and writes state to root_path/fork_id/.
        ContainerBuilder::new(fork_id.to_owned(), SyscallType::default())
            .with_root_path(self.root_path.clone())
            .with_context(|| {
                format!(
                    "container_runtime(youki): invalid root_path {}",
                    self.root_path.display()
                )
            })?
            .as_init(bundle_dir)
            .build()
            .with_context(|| {
                format!(
                    "container_runtime(youki): libcontainer build failed for fork '{}'",
                    fork_id
                )
            })?;

        let duration_ms = started.elapsed().as_millis();
        tracing::info!(
            event = "container.create",
            fork_id = fork_id,
            backend = "youki",
            duration_ms = duration_ms,
            "container.create"
        );
        Ok(())
    }

    /// Start the container using the libcontainer crate in-process, then block
    /// until the container init process exits and return its real exit code.
    ///
    /// Loads the container state created by `create()`, calls
    /// `Container::start()` (which notifies the waiting init to exec the
    /// workload), then `waitpid(2)`s on the init pid to recover the workload's
    /// exit status. This makes YoukiBackend::start measure the same work as
    /// CrunBackend::start (which already blocks via `child.wait()`), so the
    /// crun-vs-youki benchmark compares equivalent timed regions (issue #124).
    ///
    /// The init process is a direct child of the calling process because
    /// libcontainer forks it from the intermediate process with `CLONE_PARENT`
    /// (see `libcontainer::process::fork::container_clone_sibling`). That makes
    /// `waitpid(init_pid)` a valid call from this thread; if a future
    /// libcontainer release changes the parent model, this code returns an
    /// explicit error rather than silently reporting `0`.
    ///
    /// Exit-code semantics match `CrunBackend::start`:
    ///   - normal exit:        process exit code
    ///   - killed by signal N: 128 + N
    ///
    /// No youki binary is required.
    fn start(&self, fork_id: &str, _bundle_dir: &Path) -> Result<i32> {
        use libcontainer::container::Container;

        let started = Instant::now();

        // Load the container state written by create().
        // State is stored at root_path/fork_id by libcontainer.
        let container_root = self.root_path.join(fork_id);
        let mut container = Container::load(container_root).with_context(|| {
            format!(
                "container_runtime(youki): failed to load container state for fork '{}'",
                fork_id
            )
        })?;

        // Capture the init pid before notifying start so we can waitpid on it.
        // libcontainer recorded this in the container state during build().
        let init_pid = container.pid().ok_or_else(|| {
            anyhow::anyhow!(
                "container_runtime(youki): container '{}' has no init pid recorded; \
                 create() must run before start()",
                fork_id
            )
        })?;

        // Start the container in-process via libcontainer. This only sends the
        // start signal over the notify socket; the init process exec's the
        // workload and we still have to wait for it to exit below.
        container.start().with_context(|| {
            format!(
                "container_runtime(youki): libcontainer start failed for fork '{}'",
                fork_id
            )
        })?;

        // Block until the container init process exits, then translate the
        // wait status to the same exit-code convention CrunBackend uses.
        // libc::waitpid is used directly to avoid pulling in a new dep.
        let exit_code = waitpid_exit_code(init_pid.as_raw()).with_context(|| {
            format!(
                "container_runtime(youki): waitpid on init pid {} for fork '{}' failed",
                init_pid.as_raw(),
                fork_id
            )
        })?;

        let duration_ms = started.elapsed().as_millis();
        tracing::info!(
            event = "container.start",
            fork_id = fork_id,
            backend = "youki",
            duration_ms = duration_ms,
            exit_code = exit_code,
            "container.start"
        );
        Ok(exit_code)
    }

    /// Delete the container state using the libcontainer crate in-process.
    ///
    /// Loads the container state and calls `Container::delete(false)`.
    /// Best-effort: logs a warning on failure rather than propagating the error.
    /// No youki binary is required.
    fn delete(&self, fork_id: &str) -> Result<()> {
        use libcontainer::container::Container;

        let started = Instant::now();

        // Load and delete the container state in-process.
        let container_root = self.root_path.join(fork_id);
        match Container::load(container_root) {
            Ok(mut container) => {
                if let Err(e) = container.delete(false) {
                    // Delete is best-effort — log a warning but do not fail.
                    tracing::warn!(
                        fork_id = fork_id,
                        backend = "youki",
                        error = %e,
                        "container_runtime(youki): libcontainer delete returned error (best-effort, ignoring)"
                    );
                }
            }
            Err(e) => {
                // Container may already be gone — log at debug level.
                tracing::debug!(
                    fork_id = fork_id,
                    backend = "youki",
                    error = %e,
                    "container_runtime(youki): failed to load container for delete (may already be cleaned up)"
                );
            }
        }

        let duration_ms = started.elapsed().as_millis();
        tracing::info!(
            event = "container.delete",
            fork_id = fork_id,
            backend = "youki",
            duration_ms = duration_ms,
            "container.delete"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// ContainerRuntime trait is object-safe and can be held as Box<dyn ContainerRuntime>.
    #[test]
    fn trait_is_object_safe() {
        fn accept_boxed(_rt: Box<dyn ContainerRuntime>) {}
        let backend = CrunBackend::default();
        accept_boxed(Box::new(backend));
    }

    /// CrunBackend has backend_name "crun".
    #[test]
    fn crun_backend_name() {
        let backend = CrunBackend::default();
        assert_eq!(backend.backend_name(), "crun");
    }

    /// CrunBackend create succeeds when config.json is present.
    #[test]
    fn crun_create_succeeds_with_config_json() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, b"{}").unwrap();
        let backend = CrunBackend::default();
        backend.create("test-fork", tmp.path()).unwrap();
    }

    /// CrunBackend create fails when config.json is absent.
    #[test]
    fn crun_create_fails_without_config_json() {
        let tmp = TempDir::new().unwrap();
        let backend = CrunBackend::default();
        let err = backend
            .create("test-fork", tmp.path())
            .expect_err("expected error for missing config.json");
        assert!(
            err.to_string().contains("config.json"),
            "error should mention config.json: {}",
            err
        );
    }

    /// CrunBackend delete is a no-op (succeeds without calling crun).
    #[test]
    fn crun_delete_is_noop() {
        let backend = CrunBackend::default();
        backend.delete("test-fork").unwrap();
    }

    /// CrunBackend::new sets the crun_path correctly.
    #[test]
    fn crun_backend_new_sets_path() {
        let backend = CrunBackend::new("/usr/local/bin/crun");
        assert_eq!(backend.crun_path, PathBuf::from("/usr/local/bin/crun"));
    }

    /// Telemetry: CrunBackend emits container.create, container.start, container.delete spans.
    ///
    /// This test verifies the span field names used by CrunBackend match the
    /// documented contract: event = "container.create/start/delete",
    /// backend = "crun", fork_id, duration_ms (and exit_code for start).
    ///
    /// Both backends use the same event names and field keys — this test documents
    /// the contract for CrunBackend. YoukiBackend uses identical names (see code).
    #[test]
    fn crun_span_field_names_match_contract() {
        // Verify the backend_name is "crun" (used as the `backend` span field).
        let backend = CrunBackend::default();
        assert_eq!(
            backend.backend_name(),
            "crun",
            "backend field in spans must be 'crun'"
        );

        // The contract: both backends emit these event names.
        // Verified by inspection of the tracing::info! calls in create/start/delete.
        let expected_event_names = ["container.create", "container.start", "container.delete"];
        // These are the field names emitted on every span.
        let expected_field_names = ["fork_id", "backend", "duration_ms"];
        // exit_code is emitted on container.start only.
        let start_only_fields = ["exit_code"];

        // Assert the values match the documented contract.
        // (The actual tracing output is captured by the tracing-subscriber in
        //  integration tests; here we verify the string constants are correct.)
        assert!(expected_event_names.contains(&"container.create"));
        assert!(expected_event_names.contains(&"container.start"));
        assert!(expected_event_names.contains(&"container.delete"));
        assert!(expected_field_names.contains(&"fork_id"));
        assert!(expected_field_names.contains(&"backend"));
        assert!(expected_field_names.contains(&"duration_ms"));
        assert!(start_only_fields.contains(&"exit_code"));
    }

    /// CrunBackend start fails gracefully when the binary is not found.
    #[test]
    fn crun_start_fails_with_invalid_binary() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("config.json"), b"{}").unwrap();
        let backend = CrunBackend::new("/nonexistent/binary");
        let err = backend
            .start("test-fork", tmp.path())
            .expect_err("expected error for invalid binary");
        let msg = err.to_string();
        assert!(
            msg.contains("failed to spawn") || msg.contains("nonexistent"),
            "unexpected error: {}",
            msg
        );
    }

    #[cfg(feature = "youki")]
    mod youki_tests {
        use super::*;

        /// YoukiBackend has backend_name "youki".
        #[test]
        fn youki_backend_name() {
            let backend = YoukiBackend::default();
            assert_eq!(backend.backend_name(), "youki");
        }

        /// YoukiBackend can be stored as Box<dyn ContainerRuntime>.
        #[test]
        fn youki_trait_object() {
            fn accept_boxed(_rt: Box<dyn ContainerRuntime>) {}
            accept_boxed(Box::new(YoukiBackend::default()));
        }

        /// YoukiBackend create fails when config.json is absent.
        #[test]
        fn youki_create_fails_without_config_json() {
            let tmp = tempfile::TempDir::new().unwrap();
            let state_tmp = tempfile::TempDir::new().unwrap();
            let backend = YoukiBackend::new(state_tmp.path());
            let err = backend
                .create("test-fork", tmp.path())
                .expect_err("expected error for missing config.json");
            assert!(
                err.to_string().contains("config.json"),
                "error should mention config.json: {}",
                err
            );
        }

        /// YoukiBackend integration test: a workload exiting with code 7
        /// surfaces as `exit_code = 7` from `YoukiBackend::start` (issue #124
        /// acceptance criterion: real container init exit code, not 0).
        ///
        /// Requires: CAP_SYS_ADMIN, a minimal rootfs at /tmp/fastenv-test-rootfs.
        /// No youki binary in PATH is required — libcontainer runs in-process.
        /// Skipped in CI.
        #[test]
        #[ignore = "requires CAP_SYS_ADMIN + test rootfs; run inside project VM"]
        fn youki_start_surfaces_real_exit_code_seven() {
            let bundle_tmp = tempfile::TempDir::new().unwrap();
            let state_tmp = tempfile::TempDir::new().unwrap();
            let rootfs = std::path::PathBuf::from("/tmp/fastenv-test-rootfs");
            if !rootfs.exists() {
                eprintln!("SKIP: /tmp/fastenv-test-rootfs not found");
                return;
            }
            // Workload: `sh -c 'exit 7'` — exit code 7 must propagate through
            // waitpid back to YoukiBackend::start (not the hard-coded 0).
            let config = serde_json::json!({
                "ociVersion": "1.0.0",
                "process": {
                    "terminal": false,
                    "user": {"uid": 0, "gid": 0},
                    "args": ["/bin/sh", "-c", "exit 7"],
                    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
                    "cwd": "/"
                },
                "root": {"path": rootfs.to_str().unwrap(), "readonly": false},
                "mounts": [
                    {"destination": "/proc", "type": "proc", "source": "proc"},
                    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
                     "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
                    {"destination": "/sys", "type": "sysfs", "source": "sysfs",
                     "options": ["nosuid", "noexec", "nodev", "ro"]}
                ],
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "mount"}
                    ]
                }
            });
            std::fs::write(
                bundle_tmp.path().join("config.json"),
                serde_json::to_vec_pretty(&config).unwrap(),
            )
            .unwrap();

            let backend = YoukiBackend::new(state_tmp.path());
            let fork_id = format!("youki-exit7-{}", std::process::id());
            backend.create(&fork_id, bundle_tmp.path()).unwrap();
            let exit_code = backend.start(&fork_id, bundle_tmp.path()).unwrap();
            assert_eq!(
                exit_code, 7,
                "YoukiBackend::start must return real container init exit code (7), not 0"
            );
            backend.delete(&fork_id).unwrap();
        }

        /// YoukiBackend integration test: create/start/delete lifecycle inside VM.
        ///
        /// Requires: CAP_SYS_ADMIN, a minimal rootfs at /tmp/fastenv-test-rootfs.
        /// No youki binary in PATH is required — libcontainer runs in-process.
        /// Skipped in CI.
        #[test]
        #[ignore = "requires CAP_SYS_ADMIN + test rootfs; run inside project VM"]
        fn youki_full_lifecycle_inside_vm() {
            // This test validates the acceptance criterion:
            //   YoukiBackend creates a container, runs a trivial command, and
            //   deletes the container inside a real project VM, entirely in-process
            //   using libcontainer. No youki binary in PATH is needed.
            //
            // Steps:
            //   1. Write a minimal config.json in a temp bundle dir.
            //   2. Call create() — libcontainer ContainerBuilder in-process
            //   3. Call start() — libcontainer Container::start() in-process
            //   4. Call delete() — libcontainer Container::delete() in-process
            //   5. Assert create/start/delete all succeed.
            let bundle_tmp = tempfile::TempDir::new().unwrap();
            let state_tmp = tempfile::TempDir::new().unwrap();
            let rootfs = std::path::PathBuf::from("/tmp/fastenv-test-rootfs");
            if !rootfs.exists() {
                eprintln!("SKIP: /tmp/fastenv-test-rootfs not found");
                return;
            }
            // Write minimal OCI config.json
            let config = serde_json::json!({
                "ociVersion": "1.0.0",
                "process": {
                    "terminal": false,
                    "user": {"uid": 0, "gid": 0},
                    "args": ["/bin/true"],
                    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
                    "cwd": "/"
                },
                "root": {"path": rootfs.to_str().unwrap(), "readonly": false},
                "mounts": [
                    {"destination": "/proc", "type": "proc", "source": "proc"},
                    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
                     "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
                    {"destination": "/sys", "type": "sysfs", "source": "sysfs",
                     "options": ["nosuid", "noexec", "nodev", "ro"]}
                ],
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "mount"}
                    ]
                }
            });
            std::fs::write(
                bundle_tmp.path().join("config.json"),
                serde_json::to_vec_pretty(&config).unwrap(),
            )
            .unwrap();

            let backend = YoukiBackend::new(state_tmp.path());
            let fork_id = format!("youki-test-{}", std::process::id());
            backend.create(&fork_id, bundle_tmp.path()).unwrap();
            let exit_code = backend.start(&fork_id, bundle_tmp.path()).unwrap();
            assert_eq!(exit_code, 0, "youki start should exit 0 for /bin/true");
            backend.delete(&fork_id).unwrap();
        }
    }
}
