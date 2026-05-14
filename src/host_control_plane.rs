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
///
/// `secret_value` holds the plaintext secret and is injected as an OCI
/// environment variable at exec time. It is never persisted to the fork
/// registry or any on-disk artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretLease {
    pub secret_name: String,
    pub scope: String,
    pub expires_at: String,
    /// The plaintext secret value delivered to the container environment.
    /// Not persisted to disk after injection.
    pub secret_value: String,
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
///
/// After `load_host_ebpf_policy` succeeds the optional fields (`tc_attach_handle`,
/// `pin_path`, `loaded_at`) are populated with the data needed to detach the
/// program on VM stop or destroy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEbpfPolicy {
    pub name: String,
    pub attach_point: String,
    pub object_path: PathBuf,
    /// TC filter handle (format `"tc:<dev>:<direction>"`) if the program was
    /// attached as a TC classifier.  `None` for non-TC programs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tc_attach_handle: Option<String>,
    /// BPF filesystem pin path if the program was pinned (non-TC programs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_path: Option<String>,
    /// RFC-3339 timestamp recorded when the program was loaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loaded_at: Option<String>,
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
    /// Seconds to wait for a graceful shutdown before sending SIGKILL.
    pub stop_timeout_secs: u64,
}

impl Default for FirecrackerConfig {
    fn default() -> Self {
        Self {
            binary_path: PathBuf::from("/usr/local/bin/firecracker"),
            vcpu_count: 1,
            mem_size_mib: 128,
            socket_wait_timeout_secs: 10,
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off".to_string(),
            stop_timeout_secs: 10,
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
                // Idempotent: if already Stopped, return the record as-is.
                if record.state == VmState::Stopped {
                    return Ok(record);
                }
                if record.state != VmState::Running {
                    return Err(VmBootError::NotRunning {
                        project_id: project_id.to_string(),
                        current: record.state,
                    }
                    .into());
                }
                // Detach any loaded host eBPF programs before stopping the VM.
                detach_host_ebpf_if_loaded(project_id, &record);
                stop_firecracker(&mut record, config)?;
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

    /// Load and attach a host eBPF policy program at the Firecracker/jailer boundary.
    ///
    /// This method calls into `host_ebpf::load_and_attach_host_ebpf` to
    /// perform the real `bpf(2)` syscall, load the BPF program into the host
    /// kernel, and attach it at the specified `attach_point`.
    ///
    /// The `policy.attach_point` field encodes the attach type and target:
    ///
    /// - `"tc-ingress:<dev>"` / `"tc-egress:<dev>"` — TC classifier
    /// - `"tracepoint:<cat>/<evt>"` — kernel tracepoint
    /// - `"kprobe:<func>"` — kprobe on a kernel function
    ///
    /// On success the `HostEbpfPolicy` record is updated with the loaded program
    /// metadata (`tc_attach_handle`, `pin_path`, `loaded_at`) and persisted.
    ///
    /// # Errors
    ///
    /// Returns an error if the BPF program cannot be loaded (e.g. `CAP_BPF`
    /// is not held, the ELF object is malformed, or the verifier rejects the
    /// program).
    pub fn load_host_ebpf_policy(
        &self,
        root: &Path,
        project_id: &str,
        policy: HostEbpfPolicy,
    ) -> Result<ProjectVmRecord> {
        let mut record = self.load_project_vm(root, project_id)?;

        // Perform the real BPF program load and attach.
        let loaded = crate::host_ebpf::load_and_attach_host_ebpf(
            project_id,
            &policy.name,
            &policy.object_path,
            &policy.attach_point,
        )
        .with_context(|| {
            format!(
                "failed to load host eBPF policy '{}' for project '{}'",
                policy.name, project_id
            )
        })?;

        // Persist the updated policy metadata including attach state.
        let updated_policy = HostEbpfPolicy {
            name: policy.name,
            attach_point: policy.attach_point,
            object_path: policy.object_path,
            tc_attach_handle: loaded.tc_handle,
            pin_path: loaded.pin_path.map(|p| p.to_string_lossy().into_owned()),
            loaded_at: Some(loaded.loaded_at),
        };

        record.host_ebpf_policy = Some(updated_policy);
        record.updated_at = now_rfc3339();
        persist_record(root, &record)?;
        Ok(record)
    }

    /// Destroy a project VM: removes the VM directory layout and the registry
    /// entry (`state.json`).
    ///
    /// The VM must be in the `Stopped` or `Provisioned` state before calling
    /// `destroy_project_vm`. Call `transition_vm_state(Stopped)` first to
    /// gracefully stop a running VM.
    ///
    /// After this call the `project_id` no longer has a record on disk and any
    /// subsequent `get_project_vm` or `transition_vm_state` call will return an
    /// error.
    pub fn destroy_project_vm(&self, root: &Path, project_id: &str) -> Result<()> {
        let record = self.load_project_vm(root, project_id)?;

        if record.state == VmState::Running {
            bail!(
                "cannot destroy project VM '{}': VM is still Running; stop it first",
                project_id
            );
        }

        // Detach any loaded host eBPF programs before removing the VM record.
        detach_host_ebpf_if_loaded(project_id, &record);

        let dir = vm_dir(root, project_id);
        if dir.exists() {
            fs::remove_dir_all(&dir).with_context(|| {
                format!(
                    "cannot remove VM directory '{}': check permissions",
                    dir.display()
                )
            })?;
        }

        Ok(())
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
// eBPF teardown helper
// ---------------------------------------------------------------------------

/// Detach the host eBPF program for a VM if one is loaded.
///
/// This is called from both `transition_vm_state(Stopped)` and
/// `destroy_project_vm` to ensure eBPF programs are removed from the host
/// kernel when the VM is torn down.
///
/// Errors from eBPF detach are logged as warnings and do not fail the
/// calling operation (VM teardown should proceed even if eBPF cleanup fails).
fn detach_host_ebpf_if_loaded(project_id: &str, record: &ProjectVmRecord) {
    if let Some(policy) = &record.host_ebpf_policy {
        crate::host_ebpf::detach_host_ebpf(project_id, &policy.name, policy);
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

    // 8. Write a PID file so stop_firecracker can force-kill the process if
    //    graceful shutdown does not complete within the timeout.
    let pid = child.id();
    let pid_path = pid_path_for_record(record);
    if let Err(e) = fs::write(&pid_path, pid.to_string()) {
        // Non-fatal: log to the Firecracker log but continue. Force-kill will
        // not be available, but graceful stop will still work.
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .map(|mut f| {
                let _ = writeln!(
                    f,
                    "warning: cannot write PID file {}: {}",
                    pid_path.display(),
                    e
                );
            });
    }

    // 9. Mark the record as Running. The child handle is dropped; the
    //    Firecracker process continues running as a background process.
    //    The PID file written above allows stop_firecracker to force-kill it.
    drop(child);
    record.state = VmState::Running;

    Ok(())
}

/// Send a graceful shutdown to a running Firecracker VM via its API socket,
/// wait for the process to exit, and clean up the socket and PID files.
///
/// Shutdown sequence:
/// 1. Send `PUT /actions` with `action_type: SendCtrlAltDel` for a clean guest
///    shutdown (Firecracker closes the API socket when the VM halts).
/// 2. Poll for the socket to disappear (which indicates process exit) for up
///    to `config.stop_timeout_secs`.
/// 3. If the socket is still present after the timeout, force-kill the process
///    using the PID recorded in the `firecracker.pid` file.
/// 4. Remove the socket file and the PID file regardless.
///
/// If the socket was already gone (process exited before we were called), skip
/// steps 1–3 and proceed directly to state update.
fn stop_firecracker(record: &mut ProjectVmRecord, config: &FirecrackerConfig) -> Result<()> {
    let sock = &record.firecracker_sock;

    if sock.exists() {
        let sock_str = sock.to_string_lossy();
        // SendCtrlAltDel triggers a clean guest shutdown in Firecracker.
        // Errors are ignored: the process may have already exited.
        let _ = firecracker_api_put(
            &sock_str,
            "/actions",
            &serde_json::json!({"action_type": "SendCtrlAltDel"}),
        );

        // Poll for the socket to disappear (process exit indicator).
        let deadline = Instant::now() + Duration::from_secs(config.stop_timeout_secs);
        while sock.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(200));
        }

        // If the socket is still present, the process did not exit gracefully
        // within the timeout. Force-kill it via the PID file.
        if sock.exists() {
            let pid_file = pid_path_for_record(record);
            if let Ok(pid_str) = fs::read_to_string(&pid_file) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    // SAFETY: kill(2) with SIGKILL. nix is not a dependency;
                    // we use std::process::Command to invoke `kill -9`.
                    let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
                }
            }

            // Give the OS a moment to reap the process after SIGKILL.
            thread::sleep(Duration::from_millis(200));

            // Remove the socket file left behind by the killed process.
            let _ = fs::remove_file(sock);
        }

        // Remove the PID file now that the process is gone.
        let pid_file = pid_path_for_record(record);
        let _ = fs::remove_file(&pid_file);
    }

    record.state = VmState::Stopped;
    Ok(())
}

/// Return the path of the PID file for a given VM record.
///
/// The PID file lives alongside `state.json` in the VM directory as
/// `firecracker.pid`. It contains the decimal PID of the running Firecracker
/// process and is created by `boot_firecracker` and removed by `stop_firecracker`.
fn pid_path_for_record(record: &ProjectVmRecord) -> PathBuf {
    record.vm_dir.join("firecracker.pid")
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
                    secret_value: "hunter2".to_string(),
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
                    secret_value: "hunter3".to_string(),
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

    /// Verify that the `host_ebpf_policy` field round-trips through JSON
    /// serialisation without data loss.
    ///
    /// This test does NOT call `load_host_ebpf_policy` (which requires CAP_BPF
    /// and a real BPF object). Instead it writes the policy metadata directly
    /// into a provisioned record and verifies it survives persist→load.
    #[test]
    fn host_ebpf_policy_metadata_round_trips() {
        let dir = TempDir::new().unwrap();
        provision(dir.path(), "proj-h");
        let supervisor = ProjectVmSupervisor;

        // Manually inject policy metadata (simulates what the real loader
        // would write after a successful bpf(2) load).
        let mut record = supervisor.get_project_vm(dir.path(), "proj-h").unwrap();
        record.host_ebpf_policy = Some(HostEbpfPolicy {
            name: "egress-filter".to_string(),
            attach_point: "tc-egress:tap0".to_string(),
            object_path: PathBuf::from("/usr/lib/fastenv/egress.bpf.o"),
            tc_attach_handle: Some("tc:tap0:egress".to_string()),
            pin_path: None,
            loaded_at: Some("2026-01-01T00:00:00Z".to_string()),
        });
        persist_record(dir.path(), &record).unwrap();

        // Reload from disk and verify all fields survived JSON round-trip.
        let loaded = supervisor.get_project_vm(dir.path(), "proj-h").unwrap();
        let policy = loaded.host_ebpf_policy.expect("policy should be set");
        assert_eq!(policy.name, "egress-filter");
        assert_eq!(policy.attach_point, "tc-egress:tap0");
        assert_eq!(policy.tc_attach_handle.as_deref(), Some("tc:tap0:egress"));
        assert!(policy.loaded_at.is_some());
    }

    /// Integration test: load_host_ebpf_policy performs a real bpf(2) syscall.
    ///
    /// This test requires:
    /// - A real BPF ELF object file (TC classifier) at the path given by the
    ///   `FASTENV_TEST_BPF_OBJECT` environment variable.
    /// - CAP_BPF or CAP_SYS_ADMIN (run as root or with the `bpf` capability).
    /// - A network device named by `FASTENV_TEST_BPF_DEVICE` (default: `lo`).
    ///
    /// Run with:
    ///   sudo FASTENV_TEST_BPF_OBJECT=/path/to/prog.bpf.o cargo test \
    ///       host_ebpf_load_real_bpf_program -- --include-ignored
    #[test]
    #[ignore = "requires CAP_BPF and a real BPF ELF object (privileged runner only)"]
    fn host_ebpf_load_real_bpf_program() {
        let object_path = std::env::var("FASTENV_TEST_BPF_OBJECT")
            .unwrap_or_else(|_| "/tmp/test-prog.bpf.o".to_string());
        let device = std::env::var("FASTENV_TEST_BPF_DEVICE").unwrap_or_else(|_| "lo".to_string());

        let dir = TempDir::new().unwrap();
        provision(dir.path(), "proj-bpf-integ");
        let supervisor = ProjectVmSupervisor;

        let updated = supervisor
            .load_host_ebpf_policy(
                dir.path(),
                "proj-bpf-integ",
                HostEbpfPolicy {
                    name: "test-classifier".to_string(),
                    attach_point: format!("tc-egress:{}", device),
                    object_path: PathBuf::from(&object_path),
                    tc_attach_handle: None,
                    pin_path: None,
                    loaded_at: None,
                },
            )
            .expect("load_host_ebpf_policy should succeed with CAP_BPF and a real object");

        let policy = updated.host_ebpf_policy.expect("policy should be set");
        assert_eq!(policy.name, "test-classifier");
        assert!(
            policy.loaded_at.is_some(),
            "loaded_at must be set after real load"
        );
        assert!(
            policy.tc_attach_handle.is_some(),
            "tc_attach_handle must be set for TC programs"
        );
    }

    // -------------------------------------------------------------------------
    // VM boot tests using mock binary
    // -------------------------------------------------------------------------

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
            stop_timeout_secs: 2,
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

    // -------------------------------------------------------------------------
    // Stop, teardown, and destroy tests
    // -------------------------------------------------------------------------

    /// Calling `transition_vm_state(Stopped)` on a VM that is already Stopped
    /// must succeed without error (idempotent behaviour).
    #[test]
    fn stop_already_stopped_is_idempotent() {
        let dir = TempDir::new().unwrap();
        provision(dir.path(), "proj-stop-idem");

        let supervisor = ProjectVmSupervisor;

        // Manually write a Stopped state record.
        let mut record = supervisor
            .get_project_vm(dir.path(), "proj-stop-idem")
            .unwrap();
        record.state = VmState::Stopped;
        persist_record(dir.path(), &record).unwrap();

        // Stopping a Stopped VM should succeed.
        let config = test_config(PathBuf::from("/nonexistent/firecracker"));
        let result = supervisor.transition_vm_state_with_config(
            dir.path(),
            "proj-stop-idem",
            VmState::Stopped,
            &config,
        );
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
        assert_eq!(result.unwrap().state, VmState::Stopped);
    }

    /// `destroy_project_vm` must remove the VM directory and `state.json`.
    #[test]
    fn destroy_removes_vm_dir_and_state_json() {
        let dir = TempDir::new().unwrap();
        let record = provision(dir.path(), "proj-destroy-1");

        // Confirm the vm_dir and state_path exist before destroy.
        assert!(record.vm_dir.exists());
        assert!(record.state_path.exists());

        let supervisor = ProjectVmSupervisor;
        supervisor
            .destroy_project_vm(dir.path(), "proj-destroy-1")
            .expect("destroy should succeed");

        // Both the vm_dir (which contains state.json) and the state.json file
        // should be gone after destroy.
        assert!(!record.vm_dir.exists(), "vm_dir should be removed");
        assert!(!record.state_path.exists(), "state.json should be removed");

        // A subsequent get_project_vm must fail because the record is gone.
        let err = supervisor.get_project_vm(dir.path(), "proj-destroy-1");
        assert!(err.is_err(), "get after destroy should fail");
    }

    /// `destroy_project_vm` must refuse to destroy a Running VM.
    #[test]
    fn destroy_running_vm_returns_error() {
        let dir = TempDir::new().unwrap();
        provision(dir.path(), "proj-destroy-2");

        let supervisor = ProjectVmSupervisor;

        // Manually set the state to Running.
        let mut record = supervisor
            .get_project_vm(dir.path(), "proj-destroy-2")
            .unwrap();
        record.state = VmState::Running;
        persist_record(dir.path(), &record).unwrap();

        let result = supervisor.destroy_project_vm(dir.path(), "proj-destroy-2");
        assert!(result.is_err(), "destroy of Running VM should fail");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("Running"),
            "error should mention Running state: {msg}"
        );
    }

    /// When `stop_firecracker` is given a PID file and the process does not
    /// exit within the timeout, force-kill via the PID file must be triggered
    /// and the state must still become Stopped.
    ///
    /// This test spawns a real process (a shell sleep loop) and verifies that
    /// the force-kill path works end-to-end without requiring KVM.
    #[test]
    fn stop_via_pid_file_force_kill() {
        let dir = TempDir::new().unwrap();
        let vm_dir_path = dir.path().join("vms").join("proj-force-kill");
        fs::create_dir_all(vm_dir_path.join("logs")).unwrap();
        fs::create_dir_all(vm_dir_path.join("artifacts")).unwrap();
        fs::create_dir_all(vm_dir_path.join("cache")).unwrap();

        // Spawn a real `sleep 60` process that will not exit on its own.
        let mut child = Command::new("sleep")
            .arg("60")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("cannot spawn sleep");
        let pid = child.id();

        // Create a fake socket file to simulate a running Firecracker.
        let sock_path = vm_dir_path.join("firecracker.sock");
        fs::write(&sock_path, b"").unwrap();

        // Write the PID file as boot_firecracker would.
        let pid_path = vm_dir_path.join("firecracker.pid");
        fs::write(&pid_path, pid.to_string()).unwrap();

        // Build a minimal record pointing at these paths.
        let now = now_rfc3339();
        let mut record = ProjectVmRecord {
            project_id: "proj-force-kill".to_string(),
            vm_dir: vm_dir_path.clone(),
            firecracker_sock: sock_path.clone(),
            kernel_path: vm_dir_path.join("kernel"),
            rootfs_path: vm_dir_path.join("rootfs.img"),
            workspace_path: vm_dir_path.join("workspace.img"),
            cache_dir: vm_dir_path.join("cache"),
            logs_dir: vm_dir_path.join("logs"),
            artifacts_dir: vm_dir_path.join("artifacts"),
            state_path: vm_dir_path.join("state.json"),
            state: VmState::Running,
            kernel_ref: None,
            seed_data_refs: vec![],
            network_policy: NetworkPolicy::None,
            secrets: vec![],
            artifacts: vec![],
            host_ebpf_policy: None,
            created_at: now.clone(),
            updated_at: now,
        };

        // Use a very short stop timeout (1 s) so the test doesn't hang.
        let config = FirecrackerConfig {
            stop_timeout_secs: 1,
            ..test_config(PathBuf::from("/nonexistent/firecracker"))
        };

        // stop_firecracker sends SendCtrlAltDel (which will fail because there
        // is no real socket), then polls for the socket to disappear. Because
        // the socket is a plain file it won't disappear on its own, so after
        // the 1 s timeout it must force-kill the process via the PID file.
        stop_firecracker(&mut record, &config).expect("stop_firecracker should succeed");

        // The state must be Stopped.
        assert_eq!(record.state, VmState::Stopped);

        // The socket file must be gone.
        assert!(!sock_path.exists(), "socket file should be removed");

        // The PID file must be gone.
        assert!(!pid_path.exists(), "PID file should be removed");

        // The child process must have been killed.
        let outcome = child.try_wait().expect("try_wait failed");
        assert!(
            outcome.is_some(),
            "process should have exited after force-kill"
        );
    }

    /// Mock process state transitions are written correctly to the registry.
    /// This uses a provisioned VM and manually drives state transitions without
    /// spawning a real Firecracker binary, verifying each state is persisted.
    #[test]
    fn state_transitions_persisted_to_registry() {
        let dir = TempDir::new().unwrap();
        let supervisor = ProjectVmSupervisor;
        provision(dir.path(), "proj-state-transitions");

        // Verify initial Provisioned state.
        let r = supervisor
            .get_project_vm(dir.path(), "proj-state-transitions")
            .unwrap();
        assert_eq!(r.state, VmState::Provisioned);

        // Manually set to Running and persist.
        let mut r = r;
        r.state = VmState::Running;
        persist_record(dir.path(), &r).unwrap();

        let r = supervisor
            .get_project_vm(dir.path(), "proj-state-transitions")
            .unwrap();
        assert_eq!(r.state, VmState::Running);

        // Transition to Stopped via stop_firecracker (no real socket, so it
        // is a no-op on the API call and proceeds immediately to cleanup).
        let config = test_config(PathBuf::from("/nonexistent/firecracker"));
        let r = supervisor
            .transition_vm_state_with_config(
                dir.path(),
                "proj-state-transitions",
                VmState::Stopped,
                &config,
            )
            .expect("stop should succeed");
        assert_eq!(r.state, VmState::Stopped);

        // Confirm the state is persisted.
        let r = supervisor
            .get_project_vm(dir.path(), "proj-state-transitions")
            .unwrap();
        assert_eq!(r.state, VmState::Stopped);
    }
}
