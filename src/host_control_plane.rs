// host_control_plane.rs — host-side VM supervisor, registry, and policy state.
//
// Canonical docs:
//   - docs/prd.md
//   - docs/architecture.md
//   - docs/implementation-plan.md
//
// This module makes the host-control-plane surface concrete without adding a
// Firecracker dependency yet. It provisions a persistent VM record on disk,
// tracks lifecycle transitions, and keeps secrets, artifacts, network policy,
// and host eBPF policy anchored to the VM boundary instead of the workspace
// runtime.

use std::fs;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

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

/// Host-side supervisor for project VMs.
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

    pub fn transition_vm_state(
        &self,
        root: &Path,
        project_id: &str,
        state: VmState,
    ) -> Result<ProjectVmRecord> {
        let mut record = self.load_project_vm(root, project_id)?;
        record.state = state;
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
