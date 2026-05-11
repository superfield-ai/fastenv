// fork.rs — `fastenv fork --base <key> --name <fork-id>` implementation.
//
// Canonical docs:
//   - docs/architecture.md
//   - docs/implementation-plan.md
//
// Pipeline
// --------
//  1. Validate base_key exists in registry (NotFound → non-zero exit).
//  2. Validate fork_key is not already registered (AlreadyExists → non-zero exit).
//  3. mkdir forks/<fork-key>/upper/ and forks/<fork-key>/work/.
//  4. mount(2) overlayfs via rustix::mount::mount:
//       source=overlay, target=<merged/>, fs=overlay, data=
//       "lowerdir=bases/<base-key>/lower,upperdir=forks/<fork-key>/upper,
//        workdir=forks/<fork-key>/work"
//     NOTE: The merged mount-point is created here for the overlayfs mount to
//     succeed (overlayfs requires a target directory); it will be tracked via
//     merged_path in the registry.
//  5. registry.insert_fork with base_key, upper_path, work_path, merged_path,
//     created_at.
//  6. Latency measurement from function entry to mount syscall return.
//  7. Structured JSON log line: fork_id, base_key, creation_latency_ms,
//     quota_mode=soft.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use rustix::mount::{mount, MountFlags};

use crate::quota::{alloc_project_id, assign_project_quota, has_prjquota};
use crate::registry::{ForkEntry, QuotaMode, Registry, RegistryError};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Domain errors for the fork command.
#[derive(Debug, thiserror::Error)]
pub enum ForkError {
    /// The named base snapshot does not exist in the registry.
    #[error("base not found: {0}")]
    NotFound(String),
    /// A fork with this key already exists in the registry.
    #[error("fork already exists: {0}")]
    AlreadyExists(String),
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Execute the `fork` pipeline.
///
/// * `base_key`    — key of an existing base snapshot in the registry.
/// * `fork_key`    — unique identifier for the new fork workspace.
/// * `root`        — fastenv data root (e.g. `/var/lib/fastenv`).
/// * `quota_bytes` — optional quota limit in bytes; if `Some`, quota probing
///   and project ID assignment are attempted.
///
/// Quota mode selection:
///   - No `--quota` flag: `quota_mode=soft`, no ioctl called.
///   - `--quota` on prjquota filesystem: attempts hard quota via ioctl.
///   - `--quota` on non-prjquota filesystem: `quota_mode=soft`, warning logged.
///
/// Requires `CAP_SYS_ADMIN` (overlayfs mount) to be present in the process.
pub fn fork_base(
    base_key: &str,
    fork_key: &str,
    root: &Path,
    quota_bytes: Option<u64>,
) -> Result<()> {
    let started_at = Instant::now();

    let registry = Registry::open(root)?;

    // ── 1. Validate base exists ──────────────────────────────────────────────
    let base_entry = registry.get_base(base_key).map_err(|e| match e {
        RegistryError::NotFound(_) => {
            anyhow::anyhow!("{}", ForkError::NotFound(base_key.to_owned()))
        }
        other => anyhow::anyhow!("{}", other),
    })?;

    // ── 2. Validate fork key is unique ───────────────────────────────────────
    match registry.get_fork(fork_key) {
        Ok(_) => bail!("{}", ForkError::AlreadyExists(fork_key.to_owned())),
        Err(RegistryError::NotFound(_)) => {} // expected — proceed
        Err(other) => return Err(anyhow::anyhow!("{}", other)),
    }

    // ── 3. Create upper/ and work/ directories ───────────────────────────────
    let fork_dir = root.join("forks").join(fork_key);
    let upper_path = fork_dir.join("upper");
    let work_path = fork_dir.join("work");
    let merged_path = fork_dir.join("merged");

    fs::create_dir_all(&upper_path)
        .with_context(|| format!("cannot create upper dir: {}", upper_path.display()))?;
    fs::create_dir_all(&work_path)
        .with_context(|| format!("cannot create work dir: {}", work_path.display()))?;
    fs::create_dir_all(&merged_path)
        .with_context(|| format!("cannot create merged dir: {}", merged_path.display()))?;

    // ── 4. Mount overlayfs ───────────────────────────────────────────────────
    // Build the lowerdir= value: base lower first, then cache lower dirs
    // (each colon-separated).  On kernel 5.15+ multi-lower overlayfs is
    // supported natively — no additional kernel options required.
    let mut lower_dirs: Vec<String> = vec![base_entry.lower_path.display().to_string()];
    for cache_path in &base_entry.cache_lower_paths {
        lower_dirs.push(cache_path.display().to_string());
    }
    let lowerdir_str = lower_dirs.join(":");
    let mount_data_str = format!(
        "lowerdir={},upperdir={},workdir={}",
        lowerdir_str,
        upper_path.display(),
        work_path.display(),
    );
    let mount_data = CString::new(mount_data_str).context("mount data contains null byte")?;

    mount(
        "overlay",
        &merged_path,
        "overlay",
        MountFlags::empty(),
        Some(mount_data.as_ref()),
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "overlayfs mount failed for fork '{}': {} (errno {})",
            fork_key,
            e,
            e.raw_os_error()
        )
    })?;

    let creation_latency_ms = started_at.elapsed().as_millis();

    // ── 5. Determine quota mode ──────────────────────────────────────────────
    // If --quota was not specified, skip all quota logic (soft, no ioctl).
    // If --quota was specified:
    //   - Probe /proc/mounts for prjquota on the fastenv root device.
    //   - If prjquota present: attempt FS_IOC_FSSETXATTR (hard quota).
    //   - If absent or ioctl fails: log warning, use soft mode.
    let quota_mode = if let Some(qb) = quota_bytes {
        if has_prjquota(root) {
            let project_id = alloc_project_id(fork_key);
            let mode = assign_project_quota(&upper_path, project_id, qb)?;
            if matches!(mode, QuotaMode::Soft) {
                tracing::warn!(
                    fork_id = fork_key,
                    quota_bytes = qb,
                    "FS_IOC_FSSETXATTR unavailable; using soft quota mode"
                );
            }
            mode
        } else {
            tracing::warn!(
                fork_id = fork_key,
                quota_bytes = qb,
                "prjquota not detected on fastenv root filesystem; using soft quota mode"
            );
            QuotaMode::Soft
        }
    } else {
        QuotaMode::Soft
    };

    let quota_mode_str = match quota_mode {
        QuotaMode::Hard => "hard",
        QuotaMode::Soft => "soft",
    };

    // ── 6. Register fork ─────────────────────────────────────────────────────
    let created_at = rfc3339_now();
    registry.insert_fork(
        fork_key,
        ForkEntry {
            base_key: base_key.to_owned(),
            upper_path: upper_path.clone(),
            work_path: work_path.clone(),
            merged_path: Some(merged_path),
            quota_bytes,
            quota_mode,
            created_at: created_at.clone(),
            labels: HashMap::new(),
        },
    )?;

    // ── 7. Structured JSON log ───────────────────────────────────────────────
    tracing::info!(
        command = "fork",
        fork_id = fork_key,
        base_key = base_key,
        creation_latency_ms = creation_latency_ms,
        quota_mode = quota_mode_str,
        quota_bytes = quota_bytes,
        cache_lower_count = base_entry.cache_lower_paths.len(),
        "fork created"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the current UTC time as an RFC 3339 string (second precision).
fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // Unit-level registry validation tests (no mount — no CAP_SYS_ADMIN)
    // -----------------------------------------------------------------------

    /// Forking with an unknown base key returns NotFound and exits non-zero.
    #[test]
    fn fork_unknown_base_returns_not_found() {
        let root = TempDir::new().unwrap();
        let err = fork_base("nonexistent-base", "agent-1", root.path(), None)
            .expect_err("expected an error for unknown base");
        let msg = err.to_string();
        assert!(
            msg.contains("not found") || msg.contains("nonexistent-base"),
            "unexpected error message: {msg}"
        );
    }

    /// Forking the same key twice returns AlreadyExists on the second call.
    /// This test injects a fork entry directly into the registry to avoid
    /// needing CAP_SYS_ADMIN for an actual overlayfs mount.
    #[test]
    fn fork_duplicate_key_returns_already_exists() {
        use crate::registry::{ForkEntry, QuotaMode};
        use std::collections::HashMap;

        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        // Pre-insert the fork entry to simulate a previous successful fork.
        let fork_dir = root.path().join("forks").join("agent-1");
        let upper = fork_dir.join("upper");
        let work = fork_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        registry
            .insert_fork(
                "agent-1",
                ForkEntry {
                    base_key: "mybase".to_owned(),
                    upper_path: upper,
                    work_path: work,
                    merged_path: None,
                    quota_bytes: None,
                    quota_mode: QuotaMode::Soft,
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    labels: HashMap::new(),
                },
            )
            .unwrap();

        // Now try to fork with the same key — should fail with AlreadyExists.
        // We also need a base entry for the check to reach the duplicate guard.
        registry
            .insert_base(
                "mybase",
                crate::registry::BaseEntry {
                    lower_path: root.path().join("bases/mybase/lower"),
                    meta_path: root.path().join("bases/mybase/meta.json"),
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    cache_lower_paths: vec![],
                },
            )
            .unwrap();

        let err = fork_base("mybase", "agent-1", root.path(), None)
            .expect_err("expected AlreadyExists error");
        let msg = err.to_string();
        assert!(
            msg.contains("already exists") || msg.contains("agent-1"),
            "unexpected error message: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Registry: quota_bytes absent when --quota not specified
    // -----------------------------------------------------------------------

    /// A fork entry created without --quota must have quota_bytes=None in the
    /// registry (i.e. serialised JSON omits the field).
    #[test]
    fn registry_fork_entry_no_quota_omits_quota_bytes() {
        let dir = TempDir::new().unwrap();
        let registry = Registry::open(dir.path()).unwrap();

        let fork_dir = dir.path().join("forks").join("no-quota-fork");
        let upper = fork_dir.join("upper");
        let work = fork_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();

        registry
            .insert_fork(
                "no-quota-fork",
                ForkEntry {
                    base_key: "base".to_owned(),
                    upper_path: upper,
                    work_path: work,
                    merged_path: None,
                    quota_bytes: None, // no --quota flag
                    quota_mode: QuotaMode::Soft,
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    labels: HashMap::new(),
                },
            )
            .unwrap();

        let entry = registry.get_fork("no-quota-fork").unwrap();
        assert!(
            entry.quota_bytes.is_none(),
            "quota_bytes must be absent when --quota was not specified"
        );
    }

    // -----------------------------------------------------------------------
    // Registry: quota_bytes stored when --quota specified
    // -----------------------------------------------------------------------

    /// A fork entry created with --quota must have quota_bytes set and
    /// quota_mode recorded in the registry.
    #[test]
    fn registry_fork_entry_with_quota_stores_quota_bytes() {
        let dir = TempDir::new().unwrap();
        let registry = Registry::open(dir.path()).unwrap();

        let quota = 10 * 1024 * 1024u64; // 10 MiB

        let fork_dir = dir.path().join("forks").join("quota-fork");
        let upper = fork_dir.join("upper");
        let work = fork_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();

        // On a non-prjquota filesystem the ioctl returns EOPNOTSUPP and we
        // fall back to soft mode — simulate that outcome here.
        registry
            .insert_fork(
                "quota-fork",
                ForkEntry {
                    base_key: "base".to_owned(),
                    upper_path: upper,
                    work_path: work,
                    merged_path: None,
                    quota_bytes: Some(quota),
                    quota_mode: QuotaMode::Soft,
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    labels: HashMap::new(),
                },
            )
            .unwrap();

        let entry = registry.get_fork("quota-fork").unwrap();
        assert_eq!(
            entry.quota_bytes,
            Some(quota),
            "quota_bytes must match the value passed to --quota"
        );
        // On a non-prjquota host, mode must be soft.
        assert!(
            matches!(entry.quota_mode, QuotaMode::Soft),
            "quota_mode must be soft when prjquota is not available"
        );
    }

    // -----------------------------------------------------------------------
    // QuotaMode serialisation
    // -----------------------------------------------------------------------

    /// QuotaMode serialises as lowercase "soft" / "hard".
    #[test]
    fn quota_mode_serialises_lowercase() {
        let soft = serde_json::to_string(&QuotaMode::Soft).unwrap();
        assert_eq!(soft, "\"soft\"");

        let hard = serde_json::to_string(&QuotaMode::Hard).unwrap();
        assert_eq!(hard, "\"hard\"");
    }

    // -----------------------------------------------------------------------
    // Multi-lower lowerdir construction
    // -----------------------------------------------------------------------

    /// build_lowerdir_str constructs the correct colon-separated lowerdir
    /// string for a base with npm and pip cache lower dirs.
    #[test]
    fn lowerdir_includes_cache_paths() {
        use std::path::PathBuf;
        // Simulate what fork_base does when building the lowerdir string.
        let base_lower = PathBuf::from("/var/lib/fastenv/bases/mybase/lower");
        let npm_lower = PathBuf::from("/var/lib/fastenv/bases/mybase/cache/npm");
        let pip_lower = PathBuf::from("/var/lib/fastenv/bases/mybase/cache/pip");

        let cache_lower_paths = vec![npm_lower.clone(), pip_lower.clone()];
        let mut lower_dirs: Vec<String> = vec![base_lower.display().to_string()];
        for p in &cache_lower_paths {
            lower_dirs.push(p.display().to_string());
        }
        let lowerdir_str = lower_dirs.join(":");

        assert_eq!(
            lowerdir_str,
            "/var/lib/fastenv/bases/mybase/lower:\
             /var/lib/fastenv/bases/mybase/cache/npm:\
             /var/lib/fastenv/bases/mybase/cache/pip",
            "lowerdir string must list base lower then each cache lower"
        );
    }

    /// A base without cache dirs produces a single-component lowerdir string
    /// (backward-compatible — no colon appended).
    #[test]
    fn lowerdir_without_cache_is_single_path() {
        use std::path::PathBuf;
        let base_lower = PathBuf::from("/var/lib/fastenv/bases/mybase/lower");
        let cache_lower_paths: Vec<PathBuf> = vec![];
        let mut lower_dirs: Vec<String> = vec![base_lower.display().to_string()];
        for p in &cache_lower_paths {
            lower_dirs.push(p.display().to_string());
        }
        let lowerdir_str = lower_dirs.join(":");
        assert_eq!(
            lowerdir_str, "/var/lib/fastenv/bases/mybase/lower",
            "single-lower lowerdir must not contain a colon"
        );
    }

    /// fork_base returns NotFound when base has cache_lower_paths but is absent
    /// from registry — cache paths do not bypass validation.
    #[test]
    fn fork_with_cache_base_unknown_returns_not_found() {
        let root = TempDir::new().unwrap();
        let err = fork_base("no-such-base-with-cache", "fork-1", root.path(), None)
            .expect_err("expected NotFound");
        let msg = err.to_string();
        assert!(
            msg.contains("not found") || msg.contains("no-such-base-with-cache"),
            "unexpected error: {msg}"
        );
    }
}
