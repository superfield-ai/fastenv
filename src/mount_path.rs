// mount_path.rs — `fastenv mount-path <fork-id>` and `fastenv unmount <fork-id>` implementation.
//
// Canonical docs:
//   - docs/architecture.md
//   - docs/implementation-plan.md
//
// mount-path pipeline
// -------------------
//  1. Validate fork_key exists in registry (NotFound → non-zero exit).
//  2. If merged_path is already set and currently mounted, print JSON and return (idempotent).
//  3. Create forks/<fork-key>/merged/ if absent.
//  4. Bind-mount the existing overlayfs merged view at merged/ via MS_BIND.
//  5. Update registry fork entry with merged_path.
//  6. Print JSON: { "fork_id": "...", "mount_path": "..." }.
//
// unmount pipeline
// ----------------
//  1. Validate fork_key exists in registry (NotFound → non-zero exit).
//  2. If merged_path is absent or not currently mounted, exit non-zero.
//  3. umount2 on merged/ (MNT_DETACH).
//  4. Remove merged/ directory.
//  5. Clear merged_path from registry.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rustix::mount::{mount, unmount, MountFlags, UnmountFlags};
use serde::Serialize;

use crate::registry::{Registry, RegistryError};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Domain errors for the mount-path / unmount commands.
#[derive(Debug, thiserror::Error)]
pub enum MountPathError {
    /// The named fork does not exist in the registry.
    #[error("fork not found: {0}")]
    NotFound(String),
    /// unmount called on a fork that has no active merged mount.
    #[error("fork '{0}' has no active merged mount")]
    NotMounted(String),
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct MountPathOutput<'a> {
    fork_id: &'a str,
    mount_path: String,
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Execute the `mount-path` pipeline.
///
/// * `fork_key` — identifier of the fork.
/// * `root`     — fastenv data root (e.g. `/var/lib/fastenv`).
///
/// Prints JSON containing `fork_id` and `mount_path` on success.
/// Idempotent: if merged/ is already mounted, returns existing path without error.
#[deprecated(note = "Use boundary::GuestRuntime::mount_path instead.")]
pub fn mount_path(fork_key: &str, root: &Path) -> Result<()> {
    let registry = Registry::open(root)?;

    // ── 1. Validate fork exists ──────────────────────────────────────────────
    let entry = registry.get_fork(fork_key).map_err(|e| match e {
        RegistryError::NotFound(_) => {
            anyhow::anyhow!("{}", MountPathError::NotFound(fork_key.to_owned()))
        }
        other => anyhow::anyhow!("{}", other),
    })?;

    // ── 2. Idempotency: return existing path if already mounted ──────────────
    if let Some(ref existing) = entry.merged_path {
        if is_mounted(existing)? {
            let out = MountPathOutput {
                fork_id: fork_key,
                mount_path: existing.display().to_string(),
            };
            println!("{}", serde_json::to_string(&out)?);
            tracing::info!(
                command = "mount-path",
                fork_id = fork_key,
                mount_path = %existing.display(),
                "already mounted — returning existing path"
            );
            return Ok(());
        }
    }

    // ── 3. Create merged/ directory if absent ───────────────────────────────
    let fork_dir = root.join("forks").join(fork_key);
    let merged_path = fork_dir.join("merged");

    fs::create_dir_all(&merged_path)
        .with_context(|| format!("cannot create merged dir: {}", merged_path.display()))?;

    // ── 4. Bind-mount the overlayfs merged view at merged/ ──────────────────
    //
    // The fork's overlayfs is already mounted at the path given when `fork`
    // was called.  We need to expose it at a stable, well-known host path
    // (forks/<fork-key>/merged/) so virtiofsd can serve it.
    //
    // Strategy: use the existing merged view from the fork's overlayfs as the
    // bind-mount source.  The existing merged view is the fork's upper+lower
    // merged directory (which is the same as merged/ created during `fork`).
    // We bind-mount it onto our new merged/ path so virtiofsd can get a stable
    // path independent of any future remounts.
    //
    // If the fork already has a merged_path recorded (but is not mounted), use
    // that as the source; otherwise derive the fork_dir/merged path as source.
    let source_path: PathBuf = entry
        .merged_path
        .clone()
        .unwrap_or_else(|| fork_dir.join("merged"));

    mount(
        &source_path,
        &merged_path,
        "none",
        MountFlags::BIND,
        None::<&std::ffi::CStr>,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "bind-mount for fork '{}' (source '{}' → '{}') failed: {} (errno {})",
            fork_key,
            source_path.display(),
            merged_path.display(),
            e,
            e.raw_os_error()
        )
    })?;

    // ── 5. Update registry with merged_path ──────────────────────────────────
    let mut updated_entry = entry;
    updated_entry.merged_path = Some(merged_path.clone());
    registry.insert_fork(fork_key, updated_entry)?;

    // ── 6. Print JSON output ──────────────────────────────────────────────────
    let out = MountPathOutput {
        fork_id: fork_key,
        mount_path: merged_path.display().to_string(),
    };
    println!("{}", serde_json::to_string(&out)?);

    tracing::info!(
        command = "mount-path",
        fork_id = fork_key,
        mount_path = %merged_path.display(),
        "merged view bind-mounted"
    );

    Ok(())
}

/// Execute the `unmount` pipeline.
///
/// * `fork_key` — identifier of the fork to unmount.
/// * `root`     — fastenv data root (e.g. `/var/lib/fastenv`).
///
/// Exits non-zero if the fork has no active merged mount.
#[deprecated(note = "Use boundary::GuestRuntime::unmount_fork instead.")]
pub fn unmount_fork(fork_key: &str, root: &Path) -> Result<()> {
    let registry = Registry::open(root)?;

    // ── 1. Validate fork exists ──────────────────────────────────────────────
    let entry = registry.get_fork(fork_key).map_err(|e| match e {
        RegistryError::NotFound(_) => {
            anyhow::anyhow!("{}", MountPathError::NotFound(fork_key.to_owned()))
        }
        other => anyhow::anyhow!("{}", other),
    })?;

    // ── 2. Validate merged/ is currently mounted ─────────────────────────────
    let merged_path = match &entry.merged_path {
        Some(p) if is_mounted(p)? => p.clone(),
        Some(_) | None => {
            bail!("{}", MountPathError::NotMounted(fork_key.to_owned()));
        }
    };

    // ── 3. Unmount merged/ ───────────────────────────────────────────────────
    unmount(&merged_path, UnmountFlags::DETACH).map_err(|e| {
        anyhow::anyhow!(
            "umount of merged path '{}' failed for fork '{}': {} (errno {})",
            merged_path.display(),
            fork_key,
            e,
            e.raw_os_error()
        )
    })?;

    // ── 4. Remove merged/ directory ──────────────────────────────────────────
    if merged_path.exists() {
        fs::remove_dir(&merged_path).with_context(|| {
            format!(
                "cannot remove merged dir '{}' after unmount for fork '{}'",
                merged_path.display(),
                fork_key
            )
        })?;
    }

    // ── 5. Clear merged_path from registry ───────────────────────────────────
    let mut updated_entry = entry;
    updated_entry.merged_path = None;
    registry.insert_fork(fork_key, updated_entry)?;

    tracing::info!(
        command = "unmount",
        fork_id = fork_key,
        outcome = "unmounted",
        "fork merged view unmounted"
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
#[allow(deprecated)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::TempDir;

    use crate::registry::{BaseEntry, ForkEntry, QuotaMode, Registry};

    fn make_fork_entry(
        base_key: &str,
        upper: PathBuf,
        work: PathBuf,
        merged: Option<PathBuf>,
    ) -> ForkEntry {
        ForkEntry {
            base_key: base_key.to_owned(),
            upper_path: upper,
            work_path: work,
            merged_path: merged,
            quota_bytes: None,
            quota_mode: QuotaMode::Soft,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            labels: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // mount-path: NotFound on unknown fork-id
    // -----------------------------------------------------------------------

    /// mount-path on an unknown fork-id returns an error containing "not found".
    #[test]
    fn mount_path_unknown_fork_returns_not_found() {
        let root = TempDir::new().unwrap();
        let err =
            mount_path("ghost-fork", root.path()).expect_err("expected an error for unknown fork");
        let msg = err.to_string();
        assert!(
            msg.contains("not found") || msg.contains("ghost-fork"),
            "unexpected error message: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // unmount: NotFound on unknown fork-id
    // -----------------------------------------------------------------------

    /// unmount on an unknown fork-id returns an error containing "not found".
    #[test]
    fn unmount_unknown_fork_returns_not_found() {
        let root = TempDir::new().unwrap();
        let err = unmount_fork("ghost-fork", root.path())
            .expect_err("expected an error for unknown fork");
        let msg = err.to_string();
        assert!(
            msg.contains("not found") || msg.contains("ghost-fork"),
            "unexpected error message: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // unmount: NotMounted when merged_path is None
    // -----------------------------------------------------------------------

    /// unmount on a fork with no merged_path returns NotMounted error.
    #[test]
    fn unmount_fork_without_merged_path_returns_not_mounted() {
        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        let fork_dir = root.path().join("forks").join("agent-1");
        let upper = fork_dir.join("upper");
        let work = fork_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();

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
                make_fork_entry("mybase", upper.clone(), work.clone(), None),
            )
            .unwrap();

        let err = unmount_fork("agent-1", root.path())
            .expect_err("expected NotMounted error for fork without merged_path");
        let msg = err.to_string();
        assert!(
            msg.contains("no active merged mount") || msg.contains("agent-1"),
            "unexpected error message: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // unmount: NotMounted when merged_path is set but directory is not mounted
    // -----------------------------------------------------------------------

    /// unmount on a fork with merged_path set but no actual mount returns NotMounted.
    #[test]
    fn unmount_fork_with_unmouted_merged_path_returns_not_mounted() {
        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        let fork_dir = root.path().join("forks").join("agent-2");
        let upper = fork_dir.join("upper");
        let work = fork_dir.join("work");
        let merged = fork_dir.join("merged");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&merged).unwrap(); // directory exists but not mounted

        registry
            .insert_fork(
                "agent-2",
                make_fork_entry("mybase", upper, work, Some(merged.clone())),
            )
            .unwrap();

        let err = unmount_fork("agent-2", root.path())
            .expect_err("expected NotMounted error for unmounted merged dir");
        let msg = err.to_string();
        assert!(
            msg.contains("no active merged mount") || msg.contains("agent-2"),
            "unexpected error message: {msg}"
        );
    }
}
