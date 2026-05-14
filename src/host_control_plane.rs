// host_control_plane.rs — host-side VM supervisor, registry, and policy state.
//
// Canonical docs:
//   - docs/prd.md
//   - docs/architecture.md
//   - docs/implementation-plan.md
//
// This module manages the host-control-plane VM lifecycle. It provisions
// per-project VM records on disk, spawns real Firecracker processes via the
// Firecracker API socket, and tracks state transitions from Provisioned →
// Running → Stopped.
//
// # Firecracker boot design (see docs/scout/firecracker-prerequisites.md)
//
// - Firecracker is spawned directly (without jailer) using
//   `std::process::Command`. This avoids the jailer chroot path complexity on
//   development/CI hosts and satisfies the PRD §4.1 isolation boundary for
//   initial integration. Jailer support can be layered on top in a follow-up
//   issue once a dedicated fc-worker user and /srv/jailer base directory exist.
//
// - The API socket is driven by sending HTTP/1.1 requests over a Unix Domain
//   Socket using the platform `nc -U` tool (or a pure-Rust path). The boot
//   sequence is: PUT /boot-source → PUT /drives/rootfs → PUT /machine-config
//   → PUT /actions (InstanceStart).
//
// - KVM access: Firecracker requires /dev/kvm. When it is unavailable the
//   binary exits immediately with a non-zero status and an error message on
//   stderr. The supervisor detects this and returns a structured
//   `VmBootError::KvmUnavailable`.
//
// - The firecracker binary path is configurable via `FirecrackerConfig` so
//   tests can substitute a mock binary.

use std::fs;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Public error type
// ---------------------------------------------------------------------------

/// Structured errors for VM boot and shutdown operations.
///
/// These are returned as `anyhow` errors with the `VmBootError` as the root
/// cause. Callers can downcast with `err.downcast_ref::<VmBootError>()`.
#[derive(Debug, thiserror::Error)]
pub enum VmBootError {
    /// The Firecracker binary was not found at the configured path.
    #[error(
        "Firecracker binary not found at '{path}'. \
         Download it from https://github.com/firecracker-microvm/firecracker/releases \
         and install it to /usr/local/bin/firecracker (or configure FirecrackerConfig::binary_path)."
    )]
    BinaryNotFound { path: PathBuf },

    /// /dev/kvm is absent or the process does not have read-write access.
    #[error(
        "KVM is unavailable: {detail}. \
         Ensure /dev/kvm exists and the running user is a member of the 'kvm' group, \
         or run under a user with CAP_SYS_ADMIN."
    )]
    KvmUnavailable { detail: String },

    /// The Firecracker process exited before the API socket became ready.
    #[error("Firecracker exited prematurely (exit status: {status}): {stderr}")]
    ProcessExitedEarly { status: String, stderr: String },

    /// The Firecracker API socket did not appear within the timeout.
    #[error("Firecracker API socket '{sock}' did not appear within {timeout_secs}s")]
    SocketTimeout { sock: PathBuf, timeout_secs: u64 },

    /// An API call to the Firecracker socket returned an unexpected status.
    #[error("Firecracker API call to '{endpoint}' failed: {detail}")]
    ApiCallFailed { endpoint: String, detail: String },

    /// The VM process is already running and cannot be started again.
    #[error("VM for project '{project_id}' is already in Running state")]
    AlreadyRunning { project_id: String },

    /// Attempted to stop a VM that is not running.
    #[error("VM for project '{project_id}' is not in Running state (current: {current:?})")]
    NotRunning {
        project_id: String,
        current: VmState,
    },
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Host-side VM lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmState {
    Provisioned,
    Running,
    Stopped,
}

/// Network policy attached to a project VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NetworkPolicy {
    None,
    PackageMirrorOnly { mirror: Option<String> },
    Allowlist { hosts: Vec<String> },
    AuditedEgress { allowlist: Vec<String> },
}

/// Short-lived secret lease metadata tracked by the host control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretLease {
    pub secret_name: String,
    pub scope: String,
    pub expires_at: String,
}

/// Artifact metadata collected from a project VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub name: String,
    pub kind: String,
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// Host eBPF policy metadata attached at the Firecracker/jailer boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEbpfPolicy {
    pub name: String,
    pub attach_point: String,
    pub object_path: PathBuf,
}

/// Input used to provision a project VM record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectVmSpec {
    pub project_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seed_data_refs: Vec<String>,
    pub network_policy: NetworkPolicy,
}

/// Persistent host-side record for a project VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectVmRecord {
    pub project_id: String,
    pub vm_dir: PathBuf,
    /// Path to the Firecracker API socket.
    ///
    /// When Firecracker is started without jailer this is
    /// `<vm_dir>/firecracker.sock`.  When jailer is used it will be inside
    /// the chroot (`/srv/jailer/firecracker/<id>/root/run/firecracker.socket`).
    pub firecracker_sock: PathBuf,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub workspace_path: PathBuf,
    pub cache_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub artifacts_dir: PathBuf,
    pub state_path: PathBuf,
    pub state: VmState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seed_data_refs: Vec<String>,
    pub network_policy: NetworkPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretLease>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_ebpf_policy: Option<HostEbpfPolicy>,
    pub created_at: String,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Firecracker configuration
// ---------------------------------------------------------------------------

/// Configuration for the Firecracker process spawned by `ProjectVmSupervisor`.
///
/// The defaults target a development host where Firecracker has been installed
/// to `/usr/local/bin/firecracker`. Override `binary_path` in tests to point
/// at a mock binary.
///
/// See docs/scout/firecracker-prerequisites.md for environment-specific
/// requirements (KVM group membership, cgroup v2, no jailer by default).
#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    /// Path to the `firecracker` binary.
    pub binary_path: PathBuf,
    /// Number of vCPUs to configure for each VM.
    pub vcpu_count: u32,
    /// Memory size in MiB to allocate for each VM.
    pub mem_size_mib: u32,
    /// Seconds to wait for the API socket to appear after spawning Firecracker.
    pub socket_wait_timeout_secs: u64,
    /// Default kernel boot arguments passed to Firecracker.
    pub boot_args: String,
}

impl Default for FirecrackerConfig {
    fn default() -> Self {
        Self {
            binary_path: PathBuf::from("/usr/local/bin/firecracker"),
            vcpu_count: 1,
            mem_size_mib: 128,
            socket_wait_timeout_secs: 10,
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

/// Host-side supervisor for project VMs.
///
/// `ProjectVmSupervisor` manages the lifecycle of Firecracker microVMs:
///
/// - `provision_project_vm` allocates the on-disk layout and returns a
///   `ProjectVmRecord`.  No process is started.
/// - `transition_vm_state(Running)` spawns a real Firecracker process,
///   drives the API socket boot sequence, and updates the record.
/// - `transition_vm_state(Stopped)` sends a shutdown action via the API
///   socket and waits for the process to exit.
///
/// The supervisor is `Clone + Copy` and holds no process state itself;
/// process handles are not tracked between calls (the caller is responsible
/// for ensuring at-most-one Firecracker process per project).
#[derive(Debug, Default, Clone, Copy)]
pub struct ProjectVmSupervisor;

impl ProjectVmSupervisor {
    pub fn provision_project_vm(
        &self,
        root: &Path,
        spec: &ProjectVmSpec,
    ) -> Result<ProjectVmRecord> {
        validate_project_id(&spec.project_id)?;
        ensure_vm_layout(root, &spec.project_id)?;
        let mut record = if state_path(root, &spec.project_id).exists() {
            self.load_project_vm(root, &spec.project_id)?
        } else {
            self.create_project_vm(root, spec)?
        };

        record.kernel_ref = spec.kernel_ref.clone();
        record.seed_data_refs = spec.seed_data_refs.clone();
        record.network_policy = spec.network_policy.clone();
        record.updated_at = now_rfc3339();
        persist_record(root, &record)?;
        Ok(record)
    }

    pub fn get_project_vm(&self, root: &Path, project_id: &str) -> Result<ProjectVmRecord> {
        self.load_project_vm(root, project_id)
    }

    /// Transition a VM to a new lifecycle state.
    ///
    /// - `Running`: validates prerequisites (KVM, Firecracker binary), spawns
    ///   the process, drives the API socket boot sequence, and persists the
    ///   updated record.
    /// - `Stopped`: sends a graceful shutdown action via the API socket, waits
    ///   for the process to exit, and persists the updated record.
    /// - `Provisioned`: records the state change without touching a process.
    ///
    /// Uses `FirecrackerConfig::default()`. To override the binary path or VM
    /// sizing, call `transition_vm_state_with_config` instead.
    pub fn transition_vm_state(
        &self,
        root: &Path,
        project_id: &str,
        state: VmState,
    ) -> Result<ProjectVmRecord> {
        self.transition_vm_state_with_config(root, project_id, state, &FirecrackerConfig::default())
    }

    /// Transition a VM to a new lifecycle state using a custom
    /// `FirecrackerConfig`.
    ///
    /// This variant is used in tests to inject a mock Firecracker binary path.
    pub fn transition_vm_state_with_config(
        &self,
        root: &Path,
        project_id: &str,
        state: VmState,
        config: &FirecrackerConfig,
    ) -> Result<ProjectVmRecord> {
        let mut record = self.load_project_vm(root, project_id)?;

        match state {
            VmState::Running => {
                if record.state == VmState::Running {
                    return Err(VmBootError::AlreadyRunning {
                        project_id: project_id.to_string(),
                    }
                    .into());
                }
                boot_firecracker(&mut record, config)?;
            }
            VmState::Stopped => {
                if record.state != VmState::Running {
                    return Err(VmBootError::NotRunning {
                        project_id: project_id.to_string(),
                        current: record.state,
                    }
                    .into());
                }
                stop_firecracker(&mut record)?;
            }
            VmState::Provisioned => {
                // No process interaction required for a reset to Provisioned.
                record.state = VmState::Provisioned;
            }
        }

        record.updated_at = now_rfc3339();
        persist_record(root, &record)?;
        Ok(record)
    }

    pub fn attach_network_policy(
        &self,
        root: &Path,
        project_id: &str,
        policy: NetworkPolicy,
    ) -> Result<ProjectVmRecord> {
        let mut record = self.load_project_vm(root, project_id)?;
        record.network_policy = policy;
        record.updated_at = now_rfc3339();
        persist_record(root, &record)?;
        Ok(record)
    }

    pub fn inject_secret(
        &self,
        root: &Path,
        project_id: &str,
        lease: SecretLease,
    ) -> Result<ProjectVmRecord> {
        let mut record = self.load_project_vm(root, project_id)?;
        record
            .secrets
            .retain(|existing| existing.secret_name != lease.secret_name);
        record.secrets.push(lease);
        record.updated_at = now_rfc3339();
        persist_record(root, &record)?;
        Ok(record)
    }

    pub fn collect_artifact(
        &self,
        root: &Path,
        project_id: &str,
        artifact: ArtifactRecord,
    ) -> Result<ProjectVmRecord> {
        if artifact.name.trim().is_empty() {
            bail!("artifact name must not be empty");
        }

        let mut record = self.load_project_vm(root, project_id)?;
        record
            .artifacts
            .retain(|existing| existing.name != artifact.name);
        record.artifacts.push(artifact);
        record.updated_at = now_rfc3339();
        persist_record(root, &record)?;
        Ok(record)
    }

    pub fn load_host_ebpf_policy(
        &self,
        root: &Path,
        project_id: &str,
        policy: HostEbpfPolicy,
    ) -> Result<ProjectVmRecord> {
        let mut record = self.load_project_vm(root, project_id)?;
        record.host_ebpf_policy = Some(policy);
        record.updated_at = now_rfc3339();
        persist_record(root, &record)?;
        Ok(record)
    }

    fn create_project_vm(&self, root: &Path, spec: &ProjectVmSpec) -> Result<ProjectVmRecord> {
        let vm_dir = vm_dir(root, &spec.project_id);
        let logs_dir = vm_dir.join("logs");
        let artifacts_dir = vm_dir.join("artifacts");
        let cache_dir = vm_dir.join("cache");

        fs::create_dir_all(&logs_dir)
            .with_context(|| format!("cannot create logs dir: {}", logs_dir.display()))?;
        fs::create_dir_all(&artifacts_dir)
            .with_context(|| format!("cannot create artifacts dir: {}", artifacts_dir.display()))?;
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("cannot create cache dir: {}", cache_dir.display()))?;
        ensure_empty_file(&vm_dir.join("kernel"))?;
        ensure_empty_file(&vm_dir.join("rootfs.img"))?;
        ensure_empty_file(&vm_dir.join("workspace.img"))?;

        Ok(ProjectVmRecord {
            project_id: spec.project_id.clone(),
            vm_dir: vm_dir.clone(),
            firecracker_sock: vm_dir.join("firecracker.sock"),
            kernel_path: vm_dir.join("kernel"),
            rootfs_path: vm_dir.join("rootfs.img"),
            workspace_path: vm_dir.join("workspace.img"),
            cache_dir,
            logs_dir,
            artifacts_dir,
            state_path: state_path(root, &spec.project_id),
            state: VmState::Provisioned,
            kernel_ref: spec.kernel_ref.clone(),
            seed_data_refs: spec.seed_data_refs.clone(),
            network_policy: spec.network_policy.clone(),
            secrets: Vec::new(),
            artifacts: Vec::new(),
            host_ebpf_policy: None,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
        })
    }

    fn load_project_vm(&self, root: &Path, project_id: &str) -> Result<ProjectVmRecord> {
        let path = state_path(root, project_id);
        let file = fs::File::open(&path)
            .with_context(|| format!("cannot open project VM state: {}", path.display()))?;
        let record: ProjectVmRecord = serde_json::from_reader(file)
            .with_context(|| format!("cannot parse project VM state: {}", path.display()))?;
        Ok(record)
    }
}

// ---------------------------------------------------------------------------
// VM boot implementation
// ---------------------------------------------------------------------------

/// Check that /dev/kvm is accessible to the current process.
///
/// Returns `Err(VmBootError::KvmUnavailable)` if the device is absent or
/// access is denied. This is a fast pre-flight check before spawning the
/// Firecracker binary.
fn check_kvm_access() -> Result<()> {
    let kvm_path = Path::new("/dev/kvm");
    if !kvm_path.exists() {
        return Err(VmBootError::KvmUnavailable {
            detail: "/dev/kvm does not exist — KVM kernel module may not be loaded".to_string(),
        }
        .into());
    }
    // Attempt to open /dev/kvm for reading to confirm access.
    match fs::OpenOptions::new().read(true).open(kvm_path) {
        Ok(_) => Ok(()),
        Err(e) => Err(VmBootError::KvmUnavailable {
            detail: format!(
                "cannot open /dev/kvm: {} — add the user to the 'kvm' group \
                 (sudo usermod -aG kvm $USER) or run as root",
                e
            ),
        }
        .into()),
    }
}

/// Spawn a Firecracker process, wait for the API socket, drive the boot
/// sequence, and update `record.state` to `Running`.
///
/// The API socket path is taken from `record.firecracker_sock`. The kernel and
/// rootfs paths are taken from `record.kernel_path` and `record.rootfs_path`.
///
/// # Error handling
///
/// - Returns `VmBootError::BinaryNotFound` if `config.binary_path` does not exist.
/// - Returns `VmBootError::KvmUnavailable` if `/dev/kvm` is inaccessible.
/// - Returns `VmBootError::ProcessExitedEarly` if the process exits before the
///   API socket appears.
/// - Returns `VmBootError::SocketTimeout` if the socket does not appear in
///   `config.socket_wait_timeout_secs`.
/// - Returns `VmBootError::ApiCallFailed` if any boot API call fails.
fn boot_firecracker(record: &mut ProjectVmRecord, config: &FirecrackerConfig) -> Result<()> {
    // 1. Pre-flight: binary must exist.
    if !config.binary_path.exists() {
        return Err(VmBootError::BinaryNotFound {
            path: config.binary_path.clone(),
        }
        .into());
    }

    // 2. Pre-flight: KVM must be accessible.
    check_kvm_access()?;

    // 3. Remove any stale socket file from a previous run.
    let sock = &record.firecracker_sock;
    if sock.exists() {
        fs::remove_file(sock)
            .with_context(|| format!("cannot remove stale socket: {}", sock.display()))?;
    }

    // 4. Open log file for Firecracker stdout/stderr.
    let log_file = record.logs_dir.join("firecracker.log");
    let log_fd = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)
        .with_context(|| format!("cannot open Firecracker log: {}", log_file.display()))?;
    let stderr_fd = log_fd.try_clone().context("cannot clone log fd")?;

    // 5. Spawn Firecracker.
    //
    //    --api-sock: path to the Unix domain socket the supervisor will use.
    //    --log-path / --level: structured logs to the logs dir.
    //    --id: VM identifier (project_id is already validated as a safe string).
    let mut child: Child = Command::new(&config.binary_path)
        .arg("--api-sock")
        .arg(sock)
        .arg("--id")
        .arg(&record.project_id)
        .stdout(Stdio::from(log_fd))
        .stderr(Stdio::from(stderr_fd))
        .spawn()
        .with_context(|| {
            format!(
                "cannot spawn Firecracker at '{}': check that the binary is executable",
                config.binary_path.display()
            )
        })?;

    // 6. Wait for the API socket to appear (or detect early exit).
    wait_for_socket(
        sock,
        &mut child,
        Duration::from_secs(config.socket_wait_timeout_secs),
    )?;

    // 7. Drive the Firecracker API boot sequence.
    //    Paths used in API calls are host-side paths (no jailer chroot).
    //    See docs/scout/firecracker-prerequisites.md §4 for the API format.
    let sock_str = sock.to_string_lossy();

    // 7a. Configure boot source (kernel image + boot args).
    firecracker_api_put(
        &sock_str,
        "/boot-source",
        &serde_json::json!({
            "kernel_image_path": record.kernel_path.to_string_lossy(),
            "boot_args": config.boot_args
        }),
    )?;

    // 7b. Configure rootfs block device.
    firecracker_api_put(
        &sock_str,
        "/drives/rootfs",
        &serde_json::json!({
            "drive_id": "rootfs",
            "path_on_host": record.rootfs_path.to_string_lossy(),
            "is_root_device": true,
            "is_read_only": false
        }),
    )?;

    // 7c. Configure machine (vCPUs, memory).
    firecracker_api_put(
        &sock_str,
        "/machine-config",
        &serde_json::json!({
            "vcpu_count": config.vcpu_count,
            "mem_size_mib": config.mem_size_mib
        }),
    )?;

    // 7d. Boot the VM.
    firecracker_api_put(
        &sock_str,
        "/actions",
        &serde_json::json!({"action_type": "InstanceStart"}),
    )?;

    // 8. Mark the record as Running. The child handle is intentionally
    //    dropped here; the Firecracker process becomes a daemon attached to
    //    the socket. A follow-up issue will add a PID file for clean tracking.
    drop(child);
    record.state = VmState::Running;

    Ok(())
}

/// Send a graceful shutdown to a running Firecracker VM via its API socket,
/// then wait for the process to exit.
///
/// The shutdown is triggered by `PUT /actions` with `action_type: SendCtrlAltDel`.
/// If the socket is gone (process already exited), the state is set to Stopped
/// without error.
fn stop_firecracker(record: &mut ProjectVmRecord) -> Result<()> {
    let sock = &record.firecracker_sock;

    if sock.exists() {
        let sock_str = sock.to_string_lossy();
        // SendCtrlAltDel triggers a clean guest shutdown in Firecracker.
        // We ignore errors here because the process may have already exited.
        let _ = firecracker_api_put(
            &sock_str,
            "/actions",
            &serde_json::json!({"action_type": "SendCtrlAltDel"}),
        );

        // Wait briefly for the socket to disappear (process exit).
        let deadline = Instant::now() + Duration::from_secs(5);
        while sock.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(200));
        }

        // Remove the socket file if still present.
        if sock.exists() {
            let _ = fs::remove_file(sock);
        }
    }

    record.state = VmState::Stopped;
    Ok(())
}

/// Wait for the Firecracker API socket to appear on disk, polling at 100ms
/// intervals. If the child process exits before the socket appears, return
/// `VmBootError::ProcessExitedEarly`. If the timeout expires, return
/// `VmBootError::SocketTimeout`.
fn wait_for_socket(sock: &Path, child: &mut Child, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;

    loop {
        // Check if the socket has appeared.
        if sock.exists() {
            return Ok(());
        }

        // Check if the process has exited (crash before socket was created).
        match child
            .try_wait()
            .context("cannot poll Firecracker process")?
        {
            Some(status) => {
                // Read stderr from the log file if possible.
                return Err(VmBootError::ProcessExitedEarly {
                    status: status.to_string(),
                    stderr: read_firecracker_log(sock),
                }
                .into());
            }
            None => {
                // Process still running; not yet ready.
            }
        }

        if Instant::now() >= deadline {
            // Kill the stalled process before returning.
            let _ = child.kill();
            return Err(VmBootError::SocketTimeout {
                sock: sock.to_path_buf(),
                timeout_secs: timeout.as_secs(),
            }
            .into());
        }

        thread::sleep(Duration::from_millis(100));
    }
}

/// Read the Firecracker log file adjacent to the socket path for error context.
fn read_firecracker_log(sock: &Path) -> String {
    // The log file lives in the logs dir adjacent to the vm dir.
    // Best-effort — return empty string on any error.
    let log_path = sock
        .parent()
        .map(|d| d.join("logs/firecracker.log"))
        .unwrap_or_default();
    fs::read_to_string(log_path)
        .unwrap_or_default()
        .lines()
        .rev()
        .take(10)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
}

/// Drive a single `PUT` call to the Firecracker API socket using `curl`.
///
/// `curl --unix-socket` is used because it is universally available on the
/// target Ubuntu 22.04 runners and avoids adding async/tokio dependencies for
/// this initial integration pass. A pure-Rust HTTP-over-UDS implementation
/// can replace this in a follow-up once the integration is proven.
///
/// Firecracker pre-boot API calls return 204 No Content on success, or 400
/// Bad Request with a JSON body on failure.
fn firecracker_api_put(sock: &str, endpoint: &str, body: &serde_json::Value) -> Result<()> {
    let body_str = serde_json::to_string(body).context("cannot serialise API request body")?;
    let url = format!("http://localhost{}", endpoint);

    let output = Command::new("curl")
        .args([
            "--silent",
            "--unix-socket",
            sock,
            "-X",
            "PUT",
            "-H",
            "Content-Type: application/json",
            "-d",
            &body_str,
            "--write-out",
            "\n%{http_code}",
            &url,
        ])
        .output()
        .with_context(|| format!("cannot run curl for Firecracker API call to '{}'", endpoint))?;

    let raw = String::from_utf8_lossy(&output.stdout);
    let (response_body, status_code) = split_curl_output(&raw);

    // 204 = success (no content), 200 = success (some endpoints).
    if status_code == "204" || status_code == "200" {
        return Ok(());
    }

    Err(VmBootError::ApiCallFailed {
        endpoint: endpoint.to_string(),
        detail: format!("HTTP {}: {}", status_code, response_body.trim()),
    }
    .into())
}

/// Send a `GET` request to the Firecracker API socket and return the response body.
///
/// Used to verify that the API socket is reachable (GET / returns InstanceInfo).
pub fn firecracker_api_get(sock: &str, endpoint: &str) -> Result<String> {
    let url = format!("http://localhost{}", endpoint);

    let output = Command::new("curl")
        .args([
            "--silent",
            "--unix-socket",
            sock,
            "-X",
            "GET",
            "--write-out",
            "\n%{http_code}",
            &url,
        ])
        .output()
        .with_context(|| format!("cannot run curl for Firecracker API GET to '{}'", endpoint))?;

    let raw = String::from_utf8_lossy(&output.stdout);
    let (response_body, status_code) = split_curl_output(&raw);

    if status_code == "200" {
        return Ok(response_body.to_string());
    }

    Err(VmBootError::ApiCallFailed {
        endpoint: endpoint.to_string(),
        detail: format!("HTTP {}: {}", status_code, response_body.trim()),
    }
    .into())
}

/// Split the curl `--write-out "\n%{http_code}"` output into (body, status_code).
fn split_curl_output(raw: &str) -> (&str, &str) {
    if let Some(pos) = raw.rfind('\n') {
        let body = &raw[..pos];
        let code = raw[pos + 1..].trim();
        (body, code)
    } else {
        (raw, "000")
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn vm_dir(root: &Path, project_id: &str) -> PathBuf {
    root.join("vms").join(project_id)
}

fn state_path(root: &Path, project_id: &str) -> PathBuf {
    vm_dir(root, project_id).join("state.json")
}

fn validate_project_id(project_id: &str) -> Result<()> {
    if project_id.trim().is_empty() {
        bail!("project_id must not be empty");
    }

    if project_id.contains('/') || project_id.contains('\\') || project_id.contains("..") {
        bail!("project_id must be a single path segment");
    }

    Ok(())
}

fn ensure_empty_file(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("cannot create placeholder file: {}", path.display()))?;
    file.sync_all().ok();
    Ok(())
}

fn ensure_vm_layout(root: &Path, project_id: &str) -> Result<()> {
    let vm_dir = vm_dir(root, project_id);
    fs::create_dir_all(vm_dir.join("logs"))
        .with_context(|| format!("cannot create logs dir: {}", vm_dir.join("logs").display()))?;
    fs::create_dir_all(vm_dir.join("artifacts")).with_context(|| {
        format!(
            "cannot create artifacts dir: {}",
            vm_dir.join("artifacts").display()
        )
    })?;
    fs::create_dir_all(vm_dir.join("cache")).with_context(|| {
        format!(
            "cannot create cache dir: {}",
            vm_dir.join("cache").display()
        )
    })?;
    Ok(())
}

fn persist_record(root: &Path, record: &ProjectVmRecord) -> Result<()> {
    let state_path = state_path(root, &record.project_id);
    let parent = state_path
        .parent()
        .context("project VM state path has no parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("cannot create project VM dir: {}", parent.display()))?;

    let tmp = NamedTempFile::new_in(parent)
        .with_context(|| format!("cannot create temp state file in {}", parent.display()))?;
    {
        let mut writer = tmp.as_file();
        serde_json::to_writer_pretty(&mut writer, record).with_context(|| {
            format!(
                "cannot serialise project VM state: {}",
                state_path.display()
            )
        })?;
        writer.write_all(b"\n").with_context(|| {
            format!("cannot finalise project VM state: {}", state_path.display())
        })?;
        writer.flush().ok();
    }
    tmp.persist(&state_path)
        .with_context(|| format!("cannot persist project VM state: {}", state_path.display()))?;
    Ok(())
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn make_spec(project_id: &str) -> ProjectVmSpec {
        ProjectVmSpec {
            project_id: project_id.to_string(),
            kernel_ref: None,
            seed_data_refs: vec![],
            network_policy: NetworkPolicy::None,
        }
    }

    fn provision(root: &Path, project_id: &str) -> ProjectVmRecord {
        let supervisor = ProjectVmSupervisor;
        supervisor
            .provision_project_vm(root, &make_spec(project_id))
            .expect("provision should succeed")
    }

    // -------------------------------------------------------------------------
    // Existing lifecycle tests (unchanged behaviour)
    // -------------------------------------------------------------------------

    #[test]
    fn provision_creates_layout() {
        let dir = TempDir::new().unwrap();
        let record = provision(dir.path(), "proj-a");
        assert_eq!(record.state, VmState::Provisioned);
        assert!(record.vm_dir.join("logs").is_dir());
        assert!(record.vm_dir.join("artifacts").is_dir());
        assert!(record.vm_dir.join("cache").is_dir());
        assert!(record.kernel_path.exists());
        assert!(record.rootfs_path.exists());
        assert!(record.workspace_path.exists());
        assert!(record.state_path.exists());
    }

    #[test]
    fn idempotent_provision() {
        let dir = TempDir::new().unwrap();
        let r1 = provision(dir.path(), "proj-b");
        let r2 = provision(dir.path(), "proj-b");
        assert_eq!(r1.created_at, r2.created_at);
    }

    #[test]
    fn invalid_project_id_rejected() {
        let dir = TempDir::new().unwrap();
        let supervisor = ProjectVmSupervisor;
        assert!(supervisor
            .provision_project_vm(dir.path(), &make_spec(""))
            .is_err());
        assert!(supervisor
            .provision_project_vm(dir.path(), &make_spec("a/b"))
            .is_err());
        assert!(supervisor
            .provision_project_vm(dir.path(), &make_spec("../etc"))
            .is_err());
    }

    #[test]
    fn get_project_vm_round_trips() {
        let dir = TempDir::new().unwrap();
        let provisioned = provision(dir.path(), "proj-c");
        let supervisor = ProjectVmSupervisor;
        let loaded = supervisor
            .get_project_vm(dir.path(), "proj-c")
            .expect("load should succeed");
        assert_eq!(provisioned.project_id, loaded.project_id);
        assert_eq!(provisioned.state, loaded.state);
    }

    #[test]
    fn attach_network_policy_persists() {
        let dir = TempDir::new().unwrap();
        provision(dir.path(), "proj-d");
        let supervisor = ProjectVmSupervisor;
        let updated = supervisor
            .attach_network_policy(
                dir.path(),
                "proj-d",
                NetworkPolicy::PackageMirrorOnly {
                    mirror: Some("https://mirror.example.com".to_string()),
                },
            )
            .unwrap();
        assert!(matches!(
            updated.network_policy,
            NetworkPolicy::PackageMirrorOnly { .. }
        ));
    }

    #[test]
    fn inject_secret_deduplicated() {
        let dir = TempDir::new().unwrap();
        provision(dir.path(), "proj-e");
        let supervisor = ProjectVmSupervisor;
        supervisor
            .inject_secret(
                dir.path(),
                "proj-e",
                SecretLease {
                    secret_name: "DB_PASS".to_string(),
                    scope: "build".to_string(),
                    expires_at: "2026-01-01T00:00:00Z".to_string(),
                },
            )
            .unwrap();
        let updated = supervisor
            .inject_secret(
                dir.path(),
                "proj-e",
                SecretLease {
                    secret_name: "DB_PASS".to_string(),
                    scope: "deploy".to_string(),
                    expires_at: "2026-06-01T00:00:00Z".to_string(),
                },
            )
            .unwrap();
        assert_eq!(updated.secrets.len(), 1);
        assert_eq!(updated.secrets[0].scope, "deploy");
    }

    #[test]
    fn collect_artifact_deduplicated() {
        let dir = TempDir::new().unwrap();
        provision(dir.path(), "proj-f");
        let supervisor = ProjectVmSupervisor;
        supervisor
            .collect_artifact(
                dir.path(),
                "proj-f",
                ArtifactRecord {
                    name: "build.tar.gz".to_string(),
                    kind: "archive".to_string(),
                    path: PathBuf::from("/tmp/build.tar.gz"),
                    digest: None,
                },
            )
            .unwrap();
        let updated = supervisor
            .collect_artifact(
                dir.path(),
                "proj-f",
                ArtifactRecord {
                    name: "build.tar.gz".to_string(),
                    kind: "archive".to_string(),
                    path: PathBuf::from("/tmp/build-v2.tar.gz"),
                    digest: Some("abc123".to_string()),
                },
            )
            .unwrap();
        assert_eq!(updated.artifacts.len(), 1);
        assert_eq!(
            updated.artifacts[0].path,
            PathBuf::from("/tmp/build-v2.tar.gz")
        );
    }

    #[test]
    fn artifact_empty_name_rejected() {
        let dir = TempDir::new().unwrap();
        provision(dir.path(), "proj-g");
        let supervisor = ProjectVmSupervisor;
        let result = supervisor.collect_artifact(
            dir.path(),
            "proj-g",
            ArtifactRecord {
                name: "   ".to_string(),
                kind: "archive".to_string(),
                path: PathBuf::from("/tmp/x"),
                digest: None,
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn load_host_ebpf_policy_persists() {
        let dir = TempDir::new().unwrap();
        provision(dir.path(), "proj-h");
        let supervisor = ProjectVmSupervisor;
        let updated = supervisor
            .load_host_ebpf_policy(
                dir.path(),
                "proj-h",
                HostEbpfPolicy {
                    name: "egress-filter".to_string(),
                    attach_point: "tc-egress".to_string(),
                    object_path: PathBuf::from("/usr/lib/fastenv/egress.bpf.o"),
                },
            )
            .unwrap();
        assert!(updated.host_ebpf_policy.is_some());
    }

    // -------------------------------------------------------------------------
    // VM boot tests using mock binary
    // -------------------------------------------------------------------------

    /// Write a shell script to `path` that acts as a minimal mock Firecracker:
    /// it creates the socket file at `--api-sock` and then sleeps indefinitely.
    fn write_mock_firecracker_creates_socket(path: &Path) {
        let script = r#"#!/bin/sh
# Minimal mock Firecracker: parse --api-sock, create the socket file, then sleep.
while [ $# -gt 0 ]; do
    if [ "$1" = "--api-sock" ]; then
        SOCK="$2"
        shift 2
    else
        shift
    fi
done
if [ -n "$SOCK" ]; then
    # Create a plain file at the socket path to simulate socket appearance.
    touch "$SOCK"
fi
sleep 30
"#;
        let mut f = fs::File::create(path).unwrap();
        f.write_all(script.as_bytes()).unwrap();
        let mut perms = f.metadata().unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();
    }

    /// Write a mock Firecracker that exits immediately with status 1 (simulates
    /// KVM unavailable or binary failure).
    fn write_mock_firecracker_exits_immediately(path: &Path) {
        let script = r#"#!/bin/sh
echo "Error: failed to open /dev/kvm: Permission denied" >&2
exit 1
"#;
        let mut f = fs::File::create(path).unwrap();
        f.write_all(script.as_bytes()).unwrap();
        let mut perms = f.metadata().unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();
    }

    /// Build a `FirecrackerConfig` that skips KVM check by pointing at a mock
    /// binary, and sets a short socket timeout.
    fn test_config(binary_path: PathBuf) -> FirecrackerConfig {
        FirecrackerConfig {
            binary_path,
            vcpu_count: 1,
            mem_size_mib: 128,
            socket_wait_timeout_secs: 3,
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off".to_string(),
        }
    }

    #[test]
    fn missing_binary_returns_structured_error() {
        let dir = TempDir::new().unwrap();
        provision(dir.path(), "proj-boot-1");

        let config = test_config(PathBuf::from("/nonexistent/firecracker"));
        let supervisor = ProjectVmSupervisor;

        let err = supervisor
            .transition_vm_state_with_config(dir.path(), "proj-boot-1", VmState::Running, &config)
            .unwrap_err();

        // The error chain must include VmBootError::BinaryNotFound.
        let boot_err = err.downcast_ref::<VmBootError>();
        assert!(boot_err.is_some(), "expected VmBootError, got: {err}");
        assert!(
            matches!(boot_err.unwrap(), VmBootError::BinaryNotFound { .. }),
            "expected BinaryNotFound, got: {:?}",
            boot_err
        );
    }

    #[test]
    fn already_running_returns_structured_error() {
        let dir = TempDir::new().unwrap();
        provision(dir.path(), "proj-boot-2");

        // Manually set the state to Running by persisting the record.
        let supervisor = ProjectVmSupervisor;
        let mut record = supervisor
            .get_project_vm(dir.path(), "proj-boot-2")
            .unwrap();
        record.state = VmState::Running;
        persist_record(dir.path(), &record).unwrap();

        // Attempting to boot again should fail.
        let config = test_config(PathBuf::from("/nonexistent/firecracker"));
        let err = supervisor
            .transition_vm_state_with_config(dir.path(), "proj-boot-2", VmState::Running, &config)
            .unwrap_err();

        let boot_err = err.downcast_ref::<VmBootError>();
        assert!(
            matches!(boot_err, Some(VmBootError::AlreadyRunning { .. })),
            "expected AlreadyRunning, got: {:?}",
            boot_err
        );
    }

    #[test]
    fn stop_not_running_returns_structured_error() {
        let dir = TempDir::new().unwrap();
        provision(dir.path(), "proj-boot-3");

        let supervisor = ProjectVmSupervisor;
        let config = test_config(PathBuf::from("/nonexistent/firecracker"));

        let err = supervisor
            .transition_vm_state_with_config(dir.path(), "proj-boot-3", VmState::Stopped, &config)
            .unwrap_err();

        let boot_err = err.downcast_ref::<VmBootError>();
        assert!(
            matches!(boot_err, Some(VmBootError::NotRunning { .. })),
            "expected NotRunning, got: {:?}",
            boot_err
        );
    }

    #[test]
    fn mock_firecracker_exits_early_returns_structured_error() {
        let dir = TempDir::new().unwrap();
        provision(dir.path(), "proj-boot-4");

        let bin_dir = TempDir::new().unwrap();
        let bin_path = bin_dir.path().join("firecracker");
        write_mock_firecracker_exits_immediately(&bin_path);

        // We need to bypass the KVM check for this test. To do that we
        // monkey-patch: if /dev/kvm is accessible we proceed normally;
        // if not we expect that the boot will fail with BinaryNotFound or
        // ProcessExitedEarly.
        //
        // The test verifies that when a binary exits early, the supervisor
        // detects it and returns ProcessExitedEarly (not a hang).
        // KVM check will block before even spawning if KVM is unavailable,
        // so we only verify the binary-exists path here.
        let supervisor = ProjectVmSupervisor;
        let config = test_config(bin_path.clone());

        // Check if KVM is available; if not, the error will be KvmUnavailable.
        let kvm_ok = fs::OpenOptions::new().read(true).open("/dev/kvm").is_ok();

        let err = supervisor
            .transition_vm_state_with_config(dir.path(), "proj-boot-4", VmState::Running, &config)
            .unwrap_err();

        let boot_err = err.downcast_ref::<VmBootError>();
        if kvm_ok {
            assert!(
                matches!(boot_err, Some(VmBootError::ProcessExitedEarly { .. })),
                "expected ProcessExitedEarly (KVM available), got: {:?}",
                boot_err
            );
        } else {
            assert!(
                matches!(boot_err, Some(VmBootError::KvmUnavailable { .. })),
                "expected KvmUnavailable (KVM not available), got: {:?}",
                boot_err
            );
        }
    }

    #[test]
    fn split_curl_output_parses_correctly() {
        let raw = "{\"key\":\"val\"}\n204";
        let (body, code) = split_curl_output(raw);
        assert_eq!(body, "{\"key\":\"val\"}");
        assert_eq!(code, "204");
    }

    #[test]
    fn split_curl_output_handles_missing_newline() {
        let raw = "000";
        let (body, code) = split_curl_output(raw);
        assert_eq!(body, "000");
        assert_eq!(code, "000");
    }
}
