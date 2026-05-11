// diff.rs — `fastenv diff <fork-id>` implementation.
//
// Canonical docs:
//   - docs/architecture.md
//   - docs/implementation-plan.md
//
// Pipeline
// --------
//  1. Look up fork_key in the registry (NotFound → non-zero exit).
//  2. Walk forks/<fork-key>/upper/ recursively.
//  3. For each entry, determine change_type:
//       - Overlayfs whiteout: char device 0:0  → deleted
//       - Overlayfs opaque whiteout (.wh..wh..opq) → deleted
//       - ".wh." prefix files                 → deleted
//       - All other files/dirs                → added or modified
//       NOTE: upper/ only contains entries that were accessed/modified by the
//       fork. We cannot distinguish "added" from "modified" from the overlay
//       alone without inspecting the lower layer; per the issue spec we emit
//       "added" for files not present in lower/ and "modified" for those that
//       are present.
//  4. Emit one newline-delimited JSON object per entry: { "path": "...", "change_type": "..." }
//  5. Exit 0 with no output if upper/ is empty.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::registry::{Registry, RegistryError};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Domain errors for the diff command.
#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    /// The named fork does not exist in the registry.
    #[error("fork not found: {0}")]
    NotFound(String),
}

// ---------------------------------------------------------------------------
// Output record
// ---------------------------------------------------------------------------

/// One line of diff output.
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct DiffEntry {
    /// Path relative to the fork root (no leading slash).
    pub path: String,
    /// The kind of change: "added", "modified", or "deleted".
    pub change_type: ChangeType,
}

#[derive(Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Execute the `diff` pipeline.
///
/// * `fork_key` — key of an existing fork in the registry.
/// * `root`     — fastenv data root (e.g. `/var/lib/fastenv`).
///
/// Writes one JSON line per changed path to stdout.
/// Returns `Ok(())` with no output when the fork has no changes.
pub fn diff_fork(fork_key: &str, root: &Path) -> Result<()> {
    let registry = Registry::open(root)?;

    // ── 1. Validate fork exists ───────────────────────────────────────────────
    let fork_entry = registry.get_fork(fork_key).map_err(|e| match e {
        RegistryError::NotFound(_) => {
            anyhow::anyhow!("{}", DiffError::NotFound(fork_key.to_owned()))
        }
        other => anyhow::anyhow!("{}", other),
    })?;

    let upper_path = &fork_entry.upper_path;
    let lower_path = {
        // Retrieve the base entry to know what's in lower (for added vs modified).
        let base_entry = registry.get_base(&fork_entry.base_key).map_err(|e| {
            anyhow::anyhow!(
                "cannot load base '{}' for fork '{}': {}",
                fork_entry.base_key,
                fork_key,
                e
            )
        })?;
        base_entry.lower_path
    };

    // ── 2. Walk upper/ ────────────────────────────────────────────────────────
    if !upper_path.exists() {
        // upper/ never created → no changes
        return Ok(());
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();

    walk_upper(upper_path, upper_path, &lower_path, &mut out)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Recursive walker
// ---------------------------------------------------------------------------

/// Walk `dir` recursively, computing paths relative to `upper_root`.
fn walk_upper(
    dir: &Path,
    upper_root: &Path,
    lower_root: &Path,
    out: &mut impl Write,
) -> Result<()> {
    let entries =
        fs::read_dir(dir).with_context(|| format!("cannot read directory: {}", dir.display()))?;

    let mut sorted: Vec<_> = entries
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("cannot list directory entries in: {}", dir.display()))?;

    // Deterministic output order.
    sorted.sort_by_key(|e| e.file_name());

    for entry in sorted {
        let entry_path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Relative path from upper root (no leading slash).
        let rel = entry_path
            .strip_prefix(upper_root)
            .expect("entry must be under upper_root");
        let rel_str = rel.to_string_lossy().to_string();

        // ── 3. Detect whiteout files ─────────────────────────────────────────
        let change_type = if is_char_whiteout(&entry_path) || name_str.starts_with(".wh.") {
            ChangeType::Deleted
        } else {
            // Determine added vs modified by checking lower layer.
            let lower_counterpart = lower_root.join(rel);
            if lower_counterpart.exists() {
                ChangeType::Modified
            } else {
                ChangeType::Added
            }
        };

        // Emit JSON line.
        let record = DiffEntry {
            path: rel_str.clone(),
            change_type,
        };
        let line = serde_json::to_string(&record).context("cannot serialise DiffEntry")?;
        writeln!(out, "{}", line).context("cannot write to stdout")?;

        // Recurse into subdirectories (but not into whiteout dirs).
        let meta = entry.metadata().context("cannot stat entry")?;
        if meta.is_dir() && !name_str.starts_with(".wh.") {
            walk_upper(&entry_path, upper_root, lower_root, out)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Whiteout detection
// ---------------------------------------------------------------------------

/// Returns true when `path` is an overlayfs character-device whiteout
/// (device number 0:0).
fn is_char_whiteout(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    use std::os::unix::fs::MetadataExt as _;

    match fs::metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_char_device() {
                // rdev 0 means major=0, minor=0 — the overlayfs whiteout convention.
                meta.rdev() == 0
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

// Bring Write into scope inside this module.
use std::io::Write;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    use crate::registry::{BaseEntry, ForkEntry, QuotaMode, Registry};

    // -----------------------------------------------------------------------
    // Helper: set up a registry with one base and one fork
    // -----------------------------------------------------------------------

    fn setup_fork(
        root: &Path,
        base_files: &[(&str, &[u8])],
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let registry = Registry::open(root).unwrap();

        // Create base lower/ directory with some files.
        let lower = root.join("bases/mybase/lower");
        fs::create_dir_all(&lower).unwrap();
        for (name, content) in base_files {
            let p = lower.join(name);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&p, content).unwrap();
        }

        registry
            .insert_base(
                "mybase",
                BaseEntry {
                    lower_path: lower.clone(),
                    meta_path: root.join("bases/mybase/meta.json"),
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    cache_lower_paths: vec![],
                },
            )
            .unwrap();

        // Create fork upper/ directory.
        let upper = root.join("forks/agent-1/upper");
        fs::create_dir_all(&upper).unwrap();

        registry
            .insert_fork(
                "agent-1",
                ForkEntry {
                    base_key: "mybase".to_owned(),
                    upper_path: upper.clone(),
                    work_path: root.join("forks/agent-1/work"),
                    merged_path: None,
                    quota_bytes: None,
                    quota_mode: QuotaMode::Soft,
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    labels: HashMap::new(),
                },
            )
            .unwrap();

        (lower, upper)
    }

    // -----------------------------------------------------------------------
    // Helper: collect diff output as Vec<DiffEntry>
    // -----------------------------------------------------------------------

    fn run_diff(root: &Path) -> Vec<DiffEntry> {
        let mut buf: Vec<u8> = Vec::new();

        let registry = Registry::open(root).unwrap();
        let fork = registry.get_fork("agent-1").unwrap();
        let base = registry.get_base(&fork.base_key).unwrap();

        walk_upper(
            &fork.upper_path,
            &fork.upper_path,
            &base.lower_path,
            &mut buf,
        )
        .unwrap();

        buf.split(|&b| b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }

    // -----------------------------------------------------------------------
    // Unknown fork → non-zero exit (NotFound error)
    // -----------------------------------------------------------------------

    #[test]
    fn diff_unknown_fork_returns_not_found() {
        let root = TempDir::new().unwrap();
        let err = diff_fork("nonexistent-fork", root.path())
            .expect_err("expected error for unknown fork");
        let msg = err.to_string();
        assert!(
            msg.contains("not found") || msg.contains("nonexistent-fork"),
            "unexpected error message: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Empty upper → empty diff
    // -----------------------------------------------------------------------

    #[test]
    fn diff_empty_upper_produces_no_output() {
        let root = TempDir::new().unwrap();
        setup_fork(root.path(), &[("existing.txt", b"hello")]);
        // upper/ is empty — no writes were made inside the fork.
        let entries = run_diff(root.path());
        assert!(
            entries.is_empty(),
            "expected empty diff, got: {:?}",
            entries
        );
    }

    // -----------------------------------------------------------------------
    // New file in upper → added
    // -----------------------------------------------------------------------

    #[test]
    fn diff_new_file_reported_as_added() {
        let root = TempDir::new().unwrap();
        let (_, upper) = setup_fork(root.path(), &[]);
        fs::write(upper.join("newfile.txt"), b"content").unwrap();

        let entries = run_diff(root.path());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "newfile.txt");
        assert_eq!(entries[0].change_type, ChangeType::Added);
    }

    // -----------------------------------------------------------------------
    // Modified file in upper → modified
    // -----------------------------------------------------------------------

    #[test]
    fn diff_modified_file_reported_as_modified() {
        let root = TempDir::new().unwrap();
        let (_, upper) = setup_fork(root.path(), &[("existing.txt", b"original")]);
        fs::write(upper.join("existing.txt"), b"changed").unwrap();

        let entries = run_diff(root.path());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "existing.txt");
        assert_eq!(entries[0].change_type, ChangeType::Modified);
    }

    // -----------------------------------------------------------------------
    // Whiteout prefix file in upper → deleted
    // -----------------------------------------------------------------------

    #[test]
    fn diff_whiteout_prefix_file_reported_as_deleted() {
        let root = TempDir::new().unwrap();
        let (_, upper) = setup_fork(root.path(), &[("existing.txt", b"original")]);
        // Overlayfs creates ".wh.existing.txt" when a file is deleted inside the fork.
        fs::write(upper.join(".wh.existing.txt"), b"").unwrap();

        let entries = run_diff(root.path());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, ".wh.existing.txt");
        assert_eq!(entries[0].change_type, ChangeType::Deleted);
    }

    // -----------------------------------------------------------------------
    // Subdirectory handling
    // -----------------------------------------------------------------------

    #[test]
    fn diff_new_file_in_subdirectory() {
        let root = TempDir::new().unwrap();
        let (_, upper) = setup_fork(root.path(), &[]);
        fs::create_dir_all(upper.join("sub/dir")).unwrap();
        fs::write(upper.join("sub/dir/file.txt"), b"data").unwrap();

        let entries = run_diff(root.path());
        // Directories themselves appear as added entries.
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(
            paths.contains(&"sub/dir/file.txt"),
            "expected sub/dir/file.txt in diff, got: {:?}",
            paths
        );
        let file_entry = entries
            .iter()
            .find(|e| e.path == "sub/dir/file.txt")
            .unwrap();
        assert_eq!(file_entry.change_type, ChangeType::Added);
    }
}
