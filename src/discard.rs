// discard.rs — `fastenv discard <fork-id>` implementation.
//
// Canonical docs:
//   - docs/architecture.md
//   - docs/implementation-plan.md
//
// Pipeline
// --------
//  1. Validate fork_key exists in registry (NotFound → non-zero exit).
//  2. If merged_path is present and listed in /proc/mounts, umount2(MNT_DETACH).
//  3. std::fs::remove_dir_all on forks/<fork-key>/upper/ and forks/<fork-key>/work/.
//  4. registry.remove_fork.
//  5. Structured JSON log line: fork_id, outcome=discarded.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rustix::mount::{unmount, UnmountFlags};

use crate::registry::{Registry, RegistryError};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Domain errors for the discard command.
#[derive(Debug, thiserror::Error)]
pub enum DiscardError {
    /// The named fork does not exist in the registry.
    #[error("fork not found: {0}")]
    NotFound(String),
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Execute the `discard` pipeline.
///
/// * `fork_key` — identifier of the fork to discard.
/// * `root`     — fastenv data root (e.g. `/var/lib/fastenv`).
///
/// On success the fork's upper/ and work/ directories are removed, the
/// overlayfs (including merged/) is unmounted, and the registry entry is
/// deleted.  Exits non-zero on unknown fork-id via anyhow error propagation.
pub fn discard_fork(fork_key: &str, root: &Path) -> Result<()> {
    let registry = Registry::open(root)?;

    // ── 1. Validate fork exists ──────────────────────────────────────────────
    let entry = registry.get_fork(fork_key).map_err(|e| match e {
        RegistryError::NotFound(_) => {
            anyhow::anyhow!("{}", DiscardError::NotFound(fork_key.to_owned()))
        }
        other => anyhow::anyhow!("{}", other),
    })?;

    // ── 2. Unmount merged/ if present and currently mounted ──────────────────
    if let Some(ref merged_path) = entry.merged_path {
        if is_mounted(merged_path)? {
            unmount(merged_path, UnmountFlags::DETACH).map_err(|e| {
                anyhow::anyhow!(
                    "umount of merged path '{}' failed for fork '{}': {} (errno {})",
                    merged_path.display(),
                    fork_key,
                    e,
                    e.raw_os_error()
                )
            })?;
        }
    }

    // ── 3. Remove upper/ and work/ directories ───────────────────────────────
    let fork_dir = root.join("forks").join(fork_key);

    let upper_path = &entry.upper_path;
    if upper_path.exists() {
        fs::remove_dir_all(upper_path).with_context(|| {
            format!(
                "cannot remove upper dir '{}' for fork '{}'",
                upper_path.display(),
                fork_key
            )
        })?;
    }

    let work_path = &entry.work_path;
    if work_path.exists() {
        fs::remove_dir_all(work_path).with_context(|| {
            format!(
                "cannot remove work dir '{}' for fork '{}'",
                work_path.display(),
                fork_key
            )
        })?;
    }

    // Remove the merged/ dir if it still exists (e.g. was not a mount point,
    // or after successful unmount the empty directory remains).
    if let Some(ref merged_path) = entry.merged_path {
        if merged_path.exists() {
            fs::remove_dir(merged_path).ok(); // best-effort; directory may be non-empty on error
        }
    }

    // Remove the fork directory itself if now empty.
    if fork_dir.exists() {
        fs::remove_dir(&fork_dir).ok(); // best-effort
    }

    // ── 4. Remove registry entry ─────────────────────────────────────────────
    registry.remove_fork(fork_key).map_err(|e| {
        anyhow::anyhow!(
            "failed to remove registry entry for fork '{}': {}",
            fork_key,
            e
        )
    })?;

    // ── 5. Structured JSON log ───────────────────────────────────────────────
    tracing::info!(
        command = "discard",
        fork_id = fork_key,
        outcome = "discarded",
        "fork discarded"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return true if `path` appears as a mount target in `/proc/mounts`.
fn is_mounted(path: &Path) -> Result<bool> {
    let path_str = path
        .to_str()
        .with_context(|| format!("mount path is not valid UTF-8: {}", path.display()))?;
    let mounts = fs::read_to_string("/proc/mounts").context("cannot read /proc/mounts")?;
    Ok(mounts.lines().any(|line| {
        // Each line: device mountpoint fs options dump pass
        let mut fields = line.split_whitespace();
        let _device = fields.next();
        matches!(fields.next(), Some(mp) if mp == path_str)
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::TempDir;

    use crate::registry::{BaseEntry, ForkEntry, QuotaMode, Registry};

    fn make_fork_entry(
        base_key: &str,
        upper: std::path::PathBuf,
        work: std::path::PathBuf,
    ) -> ForkEntry {
        ForkEntry {
            base_key: base_key.to_owned(),
            upper_path: upper,
            work_path: work,
            merged_path: None,
            quota_bytes: None,
            quota_mode: QuotaMode::Soft,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            labels: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // NotFound on unknown fork-id
    // -----------------------------------------------------------------------

    /// Discarding an unknown fork-id returns an error containing "not found".
    #[test]
    fn discard_unknown_fork_returns_not_found() {
        let root = TempDir::new().unwrap();
        let err = discard_fork("ghost-fork", root.path())
            .expect_err("expected an error for unknown fork");
        let msg = err.to_string();
        assert!(
            msg.contains("not found") || msg.contains("ghost-fork"),
            "unexpected error message: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Successful discard (no actual overlayfs mount — no CAP_SYS_ADMIN needed)
    // -----------------------------------------------------------------------

    /// Create a fork entry with real upper/ and work/ directories on disk,
    /// then discard it; assert dirs are gone and registry is empty.
    #[test]
    fn discard_removes_dirs_and_registry_entry() {
        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        // Create on-disk dirs to simulate a real fork.
        let fork_dir = root.path().join("forks").join("agent-1");
        let upper = fork_dir.join("upper");
        let work = fork_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();

        // Register base and fork.
        registry
            .insert_base(
                "mybase",
                BaseEntry {
                    lower_path: root.path().join("bases/mybase/lower"),
                    meta_path: root.path().join("bases/mybase/meta.json"),
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    cache_lower_paths: vec![],
                },
            )
            .unwrap();
        registry
            .insert_fork(
                "agent-1",
                make_fork_entry("mybase", upper.clone(), work.clone()),
            )
            .unwrap();

        // Discard.
        discard_fork("agent-1", root.path()).unwrap();

        // Assert directories are gone.
        assert!(!upper.exists(), "upper/ should be removed after discard");
        assert!(!work.exists(), "work/ should be removed after discard");

        // Assert registry entry is gone.
        let forks = registry.list_forks().unwrap();
        assert!(
            !forks.contains_key("agent-1"),
            "registry should not contain agent-1 after discard"
        );
    }

    // -----------------------------------------------------------------------
    // Base is untouched after fork discard
    // -----------------------------------------------------------------------

    /// After discarding a fork, the base's lower/ directory is not removed.
    #[test]
    fn discard_does_not_remove_base() {
        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        let lower = root.path().join("bases/mybase/lower");
        fs::create_dir_all(&lower).unwrap();
        // Create a sentinel file inside lower/ to verify it is preserved.
        fs::write(lower.join("sentinel.txt"), b"keep me").unwrap();

        registry
            .insert_base(
                "mybase",
                BaseEntry {
                    lower_path: lower.clone(),
                    meta_path: root.path().join("bases/mybase/meta.json"),
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    cache_lower_paths: vec![],
                },
            )
            .unwrap();

        let fork_dir = root.path().join("forks").join("agent-2");
        let upper = fork_dir.join("upper");
        let work = fork_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        registry
            .insert_fork("agent-2", make_fork_entry("mybase", upper, work))
            .unwrap();

        discard_fork("agent-2", root.path()).unwrap();

        assert!(lower.exists(), "base lower/ must survive fork discard");
        assert!(
            lower.join("sentinel.txt").exists(),
            "sentinel file in base lower/ must survive fork discard"
        );
    }

    // -----------------------------------------------------------------------
    // list_forks returns empty after discarding the only fork
    // -----------------------------------------------------------------------

    #[test]
    fn list_forks_empty_after_discard() {
        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        let fork_dir = root.path().join("forks").join("only-fork");
        let upper = fork_dir.join("upper");
        let work = fork_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();

        registry
            .insert_fork("only-fork", make_fork_entry("some-base", upper, work))
            .unwrap();

        discard_fork("only-fork", root.path()).unwrap();

        let forks = registry.list_forks().unwrap();
        assert!(
            forks.is_empty(),
            "list_forks must return empty after discarding the only fork"
        );
    }
}
