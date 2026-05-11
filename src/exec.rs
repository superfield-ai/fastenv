// exec.rs — `fastenv exec <fork-id> -- <cmd>` implementation.
//
// Canonical docs:
//   - docs/architecture.md
//   - docs/implementation-plan.md
//   - docs/scout/phase2-findings.md
//   - docs/scout/phase3-findings.md
//
// Pipeline
// --------
//  1. Validate fork_id exists in registry; resolve merged_path.
//  2. Create a temporary OCI bundle directory (RAII cleanup on drop).
//  3. Write config.json with minimal OCI spec v1.0.0 fields, pointing
//     root.path at the fork's merged overlayfs directory.
//  4. Spawn crun as a direct subprocess with inherited stdio.
//  5. Wait for crun to exit; propagate its exit code.
//  6. Emit a structured JSON log line: fork_id, command, exit_code,
//     duration_ms, network_mode.
//  7. Bundle tmpdir is removed by RAII drop (success and error paths).

use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::registry::{Registry, RegistryError};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Options parsed from the `exec` subcommand flags.
#[derive(Debug)]
pub struct ExecOptions {
    /// Path to the crun binary (default: /usr/bin/crun).
    pub crun_path: String,
    /// CPU shares (OCI cpu_shares) or cpuset (string with hyphen/comma).
    pub cpu: Option<CpuSpec>,
    /// Memory limit in bytes.
    pub memory: Option<u64>,
    /// Network mode: None = inherit, Some("none") = isolated, Some("host") = host.
    pub network: Option<String>,
}

/// CPU resource specification.
#[derive(Debug, Clone)]
pub enum CpuSpec {
    /// Integer → OCI cpu_shares.
    Shares(u64),
    /// String with hyphen or comma → OCI cpuset.
    Cpuset(String),
}

impl Default for ExecOptions {
    fn default() -> Self {
        ExecOptions {
            crun_path: "/usr/bin/crun".to_owned(),
            cpu: None,
            memory: None,
            network: None,
        }
    }
}

/// Parse a CPU spec from a CLI string.
/// A string containing '-' or ',' is treated as a cpuset; otherwise parsed as shares.
pub fn parse_cpu_spec(s: &str) -> Result<CpuSpec> {
    if s.contains('-') || s.contains(',') {
        Ok(CpuSpec::Cpuset(s.to_owned()))
    } else {
        let shares: u64 = s
            .parse()
            .with_context(|| format!("invalid cpu shares: {}", s))?;
        Ok(CpuSpec::Shares(shares))
    }
}

/// Execute a command inside the fork's container environment.
///
/// Returns the exit code of the command (to be used as fastenv's exit code).
///
/// * `fork_id`  — the fork's registry key.
/// * `command`  — argv[0..] to execute inside the container.
/// * `root`     — fastenv data root (e.g. `/var/lib/fastenv`).
/// * `opts`     — resource limits and crun path.
pub fn run_exec(fork_id: &str, command: &[String], root: &Path, opts: &ExecOptions) -> Result<i32> {
    let started_at = Instant::now();

    if command.is_empty() {
        bail!("exec: no command specified");
    }

    // ── 1. Resolve fork's merged path ────────────────────────────────────────
    let registry = Registry::open(root)?;
    let fork_entry = registry.get_fork(fork_id).map_err(|e| match e {
        RegistryError::NotFound(_) => {
            anyhow::anyhow!("exec: fork not found: {}", fork_id)
        }
        other => anyhow::anyhow!("exec: registry error: {}", other),
    })?;

    let merged_path = fork_entry.merged_path.ok_or_else(|| {
        anyhow::anyhow!(
            "exec: fork '{}' has no mounted overlayfs (merged_path is absent); \
             run `fastenv fork` first",
            fork_id
        )
    })?;

    if !merged_path.exists() {
        bail!(
            "exec: merged path '{}' does not exist for fork '{}'",
            merged_path.display(),
            fork_id
        );
    }

    // ── 2. Create temporary bundle directory (RAII) ──────────────────────────
    let bundle_dir = tempfile::Builder::new()
        .prefix("fastenv-bundle-")
        .tempdir()
        .context("exec: failed to create bundle tmpdir")?;

    // ── 3. Write config.json ─────────────────────────────────────────────────
    let config = build_oci_config(fork_id, command, &merged_path, opts);
    let config_path = bundle_dir.path().join("config.json");
    let config_bytes =
        serde_json::to_vec_pretty(&config).context("exec: failed to serialise config.json")?;
    std::fs::write(&config_path, &config_bytes)
        .with_context(|| format!("exec: failed to write {}", config_path.display()))?;

    // ── 4. Spawn crun subprocess ─────────────────────────────────────────────
    // Inherit stdin/stdout/stderr from the parent process.
    // Container ID = fork_id (must be unique per running container).
    let mut child = Command::new(&opts.crun_path)
        .arg("run")
        .arg("--bundle")
        .arg(bundle_dir.path())
        .arg(fork_id)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            format!(
                "exec: failed to spawn crun ({}); is crun installed?",
                opts.crun_path
            )
        })?;

    // ── 5. Wait for crun and propagate exit code ─────────────────────────────
    let status = child.wait().context("exec: wait for crun process failed")?;

    let exit_code = if let Some(code) = status.code() {
        code
    } else {
        // Terminated by signal.
        status.signal().unwrap_or(1) + 128
    };

    let duration_ms = started_at.elapsed().as_millis();

    // ── 6. Structured JSON log ───────────────────────────────────────────────
    let network_mode = opts.network.as_deref().unwrap_or("default").to_owned();
    tracing::info!(
        command = "exec",
        fork_id = fork_id,
        exec_command = ?command,
        exit_code = exit_code,
        duration_ms = duration_ms,
        network_mode = network_mode,
        "exec complete"
    );

    // ── 7. Bundle cleanup via RAII drop ──────────────────────────────────────
    // bundle_dir is dropped here, removing the tmpdir.

    Ok(exit_code)
}

// ---------------------------------------------------------------------------
// OCI config.json construction
// ---------------------------------------------------------------------------

/// OCI Runtime Specification v1.0.0 structures (subset needed for exec).
/// Validated against crun 0.17 (Ubuntu 22.04) in phase3-findings.md.

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OciConfig {
    oci_version: String,
    process: OciProcess,
    root: OciRoot,
    mounts: Vec<OciMount>,
    linux: OciLinux,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OciProcess {
    terminal: bool,
    user: OciUser,
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
}

#[derive(Debug, Serialize)]
struct OciUser {
    uid: u32,
    gid: u32,
}

#[derive(Debug, Serialize)]
struct OciRoot {
    path: String,
    readonly: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OciMount {
    destination: String,
    #[serde(rename = "type")]
    mount_type: String,
    source: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    options: Vec<String>,
}

#[derive(Debug, Serialize)]
struct OciLinux {
    namespaces: Vec<OciNamespace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resources: Option<OciResources>,
}

#[derive(Debug, Serialize)]
struct OciNamespace {
    #[serde(rename = "type")]
    ns_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct OciResources {
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu: Option<OciCpuResources>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory: Option<OciMemoryResources>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct OciCpuResources {
    #[serde(skip_serializing_if = "Option::is_none")]
    shares: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpus: Option<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct OciMemoryResources {
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<i64>,
}

/// Build the OCI config.json for this exec invocation.
fn build_oci_config(
    _fork_id: &str,
    command: &[String],
    merged_path: &Path,
    opts: &ExecOptions,
) -> OciConfig {
    // Use absolute path for root.path as validated in phase3-findings.md §3.
    let root_path = merged_path.to_string_lossy().into_owned();

    // ── Namespaces ────────────────────────────────────────────────────────────
    let mut namespaces = vec![
        OciNamespace {
            ns_type: "pid".to_owned(),
            path: None,
        },
        OciNamespace {
            ns_type: "mount".to_owned(),
            path: None,
        },
    ];

    // Network namespace: default = inherit (no entry), "none" = isolated, "host" = host path
    match opts.network.as_deref() {
        None | Some("host") => {
            // host: no network namespace entry → shares host network
        }
        Some("none") => {
            namespaces.push(OciNamespace {
                ns_type: "network".to_owned(),
                path: None,
            });
        }
        Some(other) => {
            // Unknown value — treat as host
            tracing::warn!(network = other, "unknown --network value; treating as host");
        }
    }

    // ── Resources ─────────────────────────────────────────────────────────────
    let has_resources = opts.cpu.is_some() || opts.memory.is_some();
    let resources = if has_resources {
        let cpu = opts.cpu.as_ref().map(|spec| match spec {
            CpuSpec::Shares(s) => OciCpuResources {
                shares: Some(*s),
                cpus: None,
            },
            CpuSpec::Cpuset(cs) => OciCpuResources {
                shares: None,
                cpus: Some(cs.clone()),
            },
        });
        let memory = opts.memory.map(|m| OciMemoryResources {
            limit: Some(m as i64),
        });
        Some(OciResources { cpu, memory })
    } else {
        None
    };

    OciConfig {
        oci_version: "1.0.0".to_owned(),
        process: OciProcess {
            terminal: false,
            user: OciUser { uid: 0, gid: 0 },
            args: command.to_vec(),
            env: vec![
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
            ],
            cwd: "/".to_owned(),
        },
        root: OciRoot {
            path: root_path,
            readonly: false,
        },
        mounts: vec![
            OciMount {
                destination: "/proc".to_owned(),
                mount_type: "proc".to_owned(),
                source: "proc".to_owned(),
                options: vec![],
            },
            OciMount {
                destination: "/dev".to_owned(),
                mount_type: "tmpfs".to_owned(),
                source: "tmpfs".to_owned(),
                options: vec![
                    "nosuid".to_owned(),
                    "strictatime".to_owned(),
                    "mode=755".to_owned(),
                    "size=65536k".to_owned(),
                ],
            },
            OciMount {
                destination: "/sys".to_owned(),
                mount_type: "sysfs".to_owned(),
                source: "sysfs".to_owned(),
                options: vec![
                    "nosuid".to_owned(),
                    "noexec".to_owned(),
                    "nodev".to_owned(),
                    "ro".to_owned(),
                ],
            },
        ],
        linux: OciLinux {
            namespaces,
            resources,
        },
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

    // -----------------------------------------------------------------------
    // config.json serialisation tests (no crun or CAP_SYS_ADMIN required)
    // -----------------------------------------------------------------------

    fn default_opts() -> ExecOptions {
        ExecOptions::default()
    }

    /// build_oci_config produces valid JSON with the required ociVersion field.
    #[test]
    fn oci_config_has_correct_version() {
        let command = vec!["echo".to_owned(), "hello".to_owned()];
        let merged = PathBuf::from("/tmp/test-merged");
        let opts = default_opts();
        let config = build_oci_config("agent-1", &command, &merged, &opts);
        assert_eq!(config.oci_version, "1.0.0");
    }

    /// build_oci_config serialises without error and includes process.args.
    #[test]
    fn oci_config_serialises_process_args() {
        let command = vec!["ls".to_owned(), "/".to_owned()];
        let merged = PathBuf::from("/tmp/test-merged");
        let opts = default_opts();
        let config = build_oci_config("agent-1", &command, &merged, &opts);
        let json = serde_json::to_string(&config).expect("serialise failed");
        assert!(json.contains("\"ls\""));
        assert!(json.contains("\"/\""));
    }

    /// root.path in the config uses the absolute merged_path.
    #[test]
    fn oci_config_uses_absolute_root_path() {
        let command = vec!["true".to_owned()];
        let merged = PathBuf::from("/var/lib/fastenv/forks/agent-1/merged");
        let opts = default_opts();
        let config = build_oci_config("agent-1", &command, &merged, &opts);
        assert_eq!(config.root.path, "/var/lib/fastenv/forks/agent-1/merged");
        assert!(!config.root.readonly);
    }

    /// pid and mount namespaces are always present.
    #[test]
    fn oci_config_has_pid_and_mount_namespaces() {
        let command = vec!["true".to_owned()];
        let merged = PathBuf::from("/tmp/merged");
        let opts = default_opts();
        let config = build_oci_config("agent-1", &command, &merged, &opts);
        let types: Vec<&str> = config
            .linux
            .namespaces
            .iter()
            .map(|n| n.ns_type.as_str())
            .collect();
        assert!(types.contains(&"pid"), "pid namespace missing");
        assert!(types.contains(&"mount"), "mount namespace missing");
    }

    /// --network none adds a network namespace entry.
    #[test]
    fn oci_config_network_none_adds_netns() {
        let command = vec!["true".to_owned()];
        let merged = PathBuf::from("/tmp/merged");
        let mut opts = default_opts();
        opts.network = Some("none".to_owned());
        let config = build_oci_config("agent-1", &command, &merged, &opts);
        let has_netns = config
            .linux
            .namespaces
            .iter()
            .any(|n| n.ns_type == "network");
        assert!(has_netns, "network namespace not added for --network none");
    }

    /// --network host does NOT add a network namespace entry.
    #[test]
    fn oci_config_network_host_no_netns() {
        let command = vec!["true".to_owned()];
        let merged = PathBuf::from("/tmp/merged");
        let mut opts = default_opts();
        opts.network = Some("host".to_owned());
        let config = build_oci_config("agent-1", &command, &merged, &opts);
        let has_netns = config
            .linux
            .namespaces
            .iter()
            .any(|n| n.ns_type == "network");
        assert!(
            !has_netns,
            "network namespace should not be present for --network host"
        );
    }

    /// Memory limit is serialised into resources when --memory is set.
    #[test]
    fn oci_config_memory_limit_serialised() {
        let command = vec!["true".to_owned()];
        let merged = PathBuf::from("/tmp/merged");
        let mut opts = default_opts();
        opts.memory = Some(64 * 1024 * 1024); // 64 MiB
        let config = build_oci_config("agent-1", &command, &merged, &opts);
        let resources = config.linux.resources.expect("resources should be present");
        let memory = resources.memory.expect("memory should be present");
        assert_eq!(memory.limit, Some(64 * 1024 * 1024));
    }

    /// CPU shares are serialised into resources when --cpu integer is set.
    #[test]
    fn oci_config_cpu_shares_serialised() {
        let command = vec!["true".to_owned()];
        let merged = PathBuf::from("/tmp/merged");
        let mut opts = default_opts();
        opts.cpu = Some(CpuSpec::Shares(512));
        let config = build_oci_config("agent-1", &command, &merged, &opts);
        let resources = config.linux.resources.expect("resources should be present");
        let cpu = resources.cpu.expect("cpu should be present");
        assert_eq!(cpu.shares, Some(512));
        assert!(cpu.cpus.is_none());
    }

    /// CPU cpuset is serialised into resources when --cpu string is set.
    #[test]
    fn oci_config_cpu_cpuset_serialised() {
        let command = vec!["true".to_owned()];
        let merged = PathBuf::from("/tmp/merged");
        let mut opts = default_opts();
        opts.cpu = Some(CpuSpec::Cpuset("0-3".to_owned()));
        let config = build_oci_config("agent-1", &command, &merged, &opts);
        let resources = config.linux.resources.expect("resources should be present");
        let cpu = resources.cpu.expect("cpu should be present");
        assert_eq!(cpu.cpus.as_deref(), Some("0-3"));
        assert!(cpu.shares.is_none());
    }

    /// No resources section when no CPU or memory flags are given.
    #[test]
    fn oci_config_no_resources_by_default() {
        let command = vec!["true".to_owned()];
        let merged = PathBuf::from("/tmp/merged");
        let opts = default_opts();
        let config = build_oci_config("agent-1", &command, &merged, &opts);
        assert!(
            config.linux.resources.is_none(),
            "resources should be absent when no limits are specified"
        );
    }

    /// run_exec returns NotFound error for a non-existent fork.
    #[test]
    fn run_exec_fork_not_found() {
        let root = TempDir::new().unwrap();
        let opts = default_opts();
        let command = vec!["echo".to_owned(), "hello".to_owned()];
        let err = run_exec("nonexistent-fork", &command, root.path(), &opts)
            .expect_err("expected NotFound error");
        let msg = err.to_string();
        assert!(
            msg.contains("not found") || msg.contains("nonexistent-fork"),
            "unexpected error: {msg}"
        );
    }

    /// run_exec returns an error for a fork with no merged_path.
    #[test]
    fn run_exec_no_merged_path_returns_error() {
        use crate::registry::{ForkEntry, QuotaMode, Registry};
        use std::collections::HashMap;

        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        let fork_dir = root.path().join("forks").join("agent-no-mount");
        let upper = fork_dir.join("upper");
        let work = fork_dir.join("work");
        std::fs::create_dir_all(&upper).unwrap();
        std::fs::create_dir_all(&work).unwrap();

        // Insert fork with no merged_path (not yet mounted).
        registry
            .insert_fork(
                "agent-no-mount",
                ForkEntry {
                    base_key: "mybase".to_owned(),
                    upper_path: upper,
                    work_path: work,
                    merged_path: None, // not mounted
                    quota_bytes: None,
                    quota_mode: QuotaMode::Soft,
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    labels: HashMap::new(),
                },
            )
            .unwrap();

        let opts = default_opts();
        let command = vec!["echo".to_owned()];
        let err = run_exec("agent-no-mount", &command, root.path(), &opts)
            .expect_err("expected error for missing merged_path");
        let msg = err.to_string();
        assert!(
            msg.contains("merged_path") || msg.contains("mounted"),
            "unexpected error: {msg}"
        );
    }

    /// parse_cpu_spec parses integer as shares.
    #[test]
    fn parse_cpu_spec_shares() {
        match parse_cpu_spec("1024").unwrap() {
            CpuSpec::Shares(s) => assert_eq!(s, 1024),
            _ => panic!("expected Shares"),
        }
    }

    /// parse_cpu_spec parses hyphenated string as cpuset.
    #[test]
    fn parse_cpu_spec_cpuset_range() {
        match parse_cpu_spec("0-3").unwrap() {
            CpuSpec::Cpuset(cs) => assert_eq!(cs, "0-3"),
            _ => panic!("expected Cpuset"),
        }
    }

    /// parse_cpu_spec parses comma-separated string as cpuset.
    #[test]
    fn parse_cpu_spec_cpuset_list() {
        match parse_cpu_spec("0,2,4").unwrap() {
            CpuSpec::Cpuset(cs) => assert_eq!(cs, "0,2,4"),
            _ => panic!("expected Cpuset"),
        }
    }

    /// proc, dev, sys mounts are included in config.
    #[test]
    fn oci_config_includes_required_mounts() {
        let command = vec!["true".to_owned()];
        let merged = PathBuf::from("/tmp/merged");
        let opts = default_opts();
        let config = build_oci_config("agent-1", &command, &merged, &opts);
        let destinations: Vec<&str> = config
            .mounts
            .iter()
            .map(|m| m.destination.as_str())
            .collect();
        assert!(destinations.contains(&"/proc"), "/proc mount missing");
        assert!(destinations.contains(&"/dev"), "/dev mount missing");
        assert!(destinations.contains(&"/sys"), "/sys mount missing");
    }

    /// OCI config JSON output contains all required top-level fields.
    #[test]
    fn oci_config_json_contains_required_fields() {
        let command = vec!["echo".to_owned(), "test".to_owned()];
        let merged = PathBuf::from("/tmp/merged");
        let opts = default_opts();
        let config = build_oci_config("agent-1", &command, &merged, &opts);
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("\"ociVersion\""), "ociVersion missing");
        assert!(json.contains("\"process\""), "process missing");
        assert!(json.contains("\"root\""), "root missing");
        assert!(json.contains("\"mounts\""), "mounts missing");
        assert!(json.contains("\"linux\""), "linux missing");
        assert!(json.contains("\"namespaces\""), "namespaces missing");
    }
}
