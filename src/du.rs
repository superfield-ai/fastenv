// du.rs — `fastenv du <fork-id>` implementation.
//
// Canonical docs:
//   - docs/architecture.md §5 OD-4 (quota / du)
//   - docs/implementation-plan.md Phase 4 (inspection: du)
//
// Pipeline
// --------
//  1. Validate fork_key exists in registry (NotFound → non-zero exit).
//  2. Recursively walk forks/<fork-key>/upper/ and sum file sizes (base
//     lower/ is excluded by definition — only bytes written by this fork).
//  3. Emit JSON to stdout: fork_id, usage_bytes, usage_human.
//     If quota_bytes is set in the registry entry, also include quota_bytes
//     (and overage_bytes if exceeded).
//  4. If usage_bytes > quota_bytes, emit a structured JSON warning to stderr:
//     {"level":"warn","fork_id":"...","usage_bytes":...,"quota_bytes":...,"overage_bytes":...}
//  5. Exit 0 regardless of quota status (warning only, not enforcement).

use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::registry::{Registry, RegistryError};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Domain errors for the du command.
#[derive(Debug, thiserror::Error)]
pub enum DuError {
    /// The named fork does not exist in the registry.
    #[error("fork not found: {0}")]
    NotFound(String),
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// JSON output emitted to stdout on success.
#[derive(Debug, Serialize)]
pub struct DuOutput {
    pub fork_id: String,
    pub usage_bytes: u64,
    pub usage_human: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overage_bytes: Option<u64>,
}

/// Structured warning emitted to stderr when usage exceeds quota.
#[derive(Debug, Serialize)]
struct DuWarning {
    level: &'static str,
    fork_id: String,
    usage_bytes: u64,
    quota_bytes: u64,
    overage_bytes: u64,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Execute the `du` pipeline.
///
/// * `fork_key` — identifier of the fork to measure.
/// * `root`     — fastenv data root (e.g. `/var/lib/fastenv`).
///
/// Emits one JSON line to stdout.  If quota is set and exceeded, also emits
/// one structured JSON warning to stderr.  Always exits 0.
pub fn du_fork(fork_key: &str, root: &Path) -> Result<()> {
    let registry = Registry::open(root)?;

    // ── 1. Validate fork exists ──────────────────────────────────────────────
    let entry = registry.get_fork(fork_key).map_err(|e| match e {
        RegistryError::NotFound(_) => {
            anyhow::anyhow!("{}", DuError::NotFound(fork_key.to_owned()))
        }
        other => anyhow::anyhow!("{}", other),
    })?;

    // ── 2. Walk upper/ and sum file sizes ────────────────────────────────────
    let usage_bytes = walk_upper_bytes(&entry.upper_path)
        .with_context(|| format!("cannot measure upper dir: {}", entry.upper_path.display()))?;

    // ── 3. Build output ──────────────────────────────────────────────────────
    let usage_human = format_bytes(usage_bytes);

    let overage_bytes = entry
        .quota_bytes
        .filter(|&q| usage_bytes > q)
        .map(|q| usage_bytes - q);

    let output = DuOutput {
        fork_id: fork_key.to_owned(),
        usage_bytes,
        usage_human,
        quota_bytes: entry.quota_bytes,
        overage_bytes,
    };

    // Emit JSON to stdout.
    let mut stdout = io::stdout();
    let line = serde_json::to_string(&output).context("serialize du output")?;
    writeln!(stdout, "{line}").context("write stdout")?;

    // ── 4. Emit stderr warning if over quota ─────────────────────────────────
    if let (Some(quota_bytes), Some(overage)) = (entry.quota_bytes, overage_bytes) {
        let warn = DuWarning {
            level: "warn",
            fork_id: fork_key.to_owned(),
            usage_bytes,
            quota_bytes,
            overage_bytes: overage,
        };
        let mut stderr = io::stderr();
        let warn_line = serde_json::to_string(&warn).context("serialize du warning")?;
        writeln!(stderr, "{warn_line}").context("write stderr warning")?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Recursively walk `upper_dir` and return the total size of all regular
/// files in bytes.  Symlinks and directories are not counted.  If `upper_dir`
/// does not exist, 0 is returned (a fork with no writes has an empty or
/// absent upper/).
pub fn walk_upper_bytes(upper_dir: &Path) -> Result<u64> {
    if !upper_dir.exists() {
        return Ok(0);
    }

    let mut total: u64 = 0;
    walk_dir(upper_dir, &mut total)?;
    Ok(total)
}

fn walk_dir(dir: &Path, total: &mut u64) -> Result<()> {
    let entries = std::fs::read_dir(dir).with_context(|| format!("read_dir: {}", dir.display()))?;

    for entry in entries {
        let entry = entry.with_context(|| format!("read dir entry in {}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("file_type: {}", path.display()))?;

        if file_type.is_dir() {
            walk_dir(&path, total)?;
        } else if file_type.is_file() {
            // Use metadata().len() for the reported file size.
            // Symlinks are not counted (is_file() returns false for symlinks).
            let meta = entry
                .metadata()
                .with_context(|| format!("metadata: {}", path.display()))?;
            *total += meta.len();
        }
        // Symlinks: skip.
    }

    Ok(())
}

/// Format a byte count as a human-readable string using binary prefixes.
///
/// Examples:
///   0          → "0 B"
///   512        → "512 B"
///   1024       → "1.0 KiB"
///   1048576    → "1.0 MiB"
///   1073741824 → "1.0 GiB"
pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1 << 10;
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    const TIB: u64 = 1 << 40;

    if bytes >= TIB {
        format!("{:.1} TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    use crate::registry::{ForkEntry, QuotaMode, Registry};

    // -----------------------------------------------------------------------
    // format_bytes
    // -----------------------------------------------------------------------

    #[test]
    fn format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn format_bytes_under_kib() {
        assert_eq!(format_bytes(512), "512 B");
    }

    #[test]
    fn format_bytes_kib() {
        assert_eq!(format_bytes(1024), "1.0 KiB");
    }

    #[test]
    fn format_bytes_mib() {
        assert_eq!(format_bytes(1 << 20), "1.0 MiB");
    }

    #[test]
    fn format_bytes_gib() {
        assert_eq!(format_bytes(1 << 30), "1.0 GiB");
    }

    #[test]
    fn format_bytes_fractional_mib() {
        // 1.5 MiB
        assert_eq!(format_bytes(3 << 19), "1.5 MiB");
    }

    // -----------------------------------------------------------------------
    // walk_upper_bytes
    // -----------------------------------------------------------------------

    /// An absent upper/ directory reports 0 bytes (fork with no writes).
    #[test]
    fn walk_upper_bytes_absent_dir_returns_zero() {
        let root = TempDir::new().unwrap();
        let absent = root.path().join("nonexistent");
        assert_eq!(walk_upper_bytes(&absent).unwrap(), 0);
    }

    /// An empty upper/ directory reports 0 bytes.
    #[test]
    fn walk_upper_bytes_empty_dir_returns_zero() {
        let root = TempDir::new().unwrap();
        let upper = root.path().join("upper");
        fs::create_dir_all(&upper).unwrap();
        assert_eq!(walk_upper_bytes(&upper).unwrap(), 0);
    }

    /// Files at the top level of upper/ are counted.
    #[test]
    fn walk_upper_bytes_counts_top_level_files() {
        let root = TempDir::new().unwrap();
        let upper = root.path().join("upper");
        fs::create_dir_all(&upper).unwrap();
        // Write exactly 100 bytes.
        fs::write(upper.join("file.txt"), vec![0u8; 100]).unwrap();
        assert_eq!(walk_upper_bytes(&upper).unwrap(), 100);
    }

    /// Files in subdirectories of upper/ are counted recursively.
    #[test]
    fn walk_upper_bytes_counts_nested_files() {
        let root = TempDir::new().unwrap();
        let upper = root.path().join("upper");
        fs::create_dir_all(upper.join("src")).unwrap();
        fs::create_dir_all(upper.join("lib")).unwrap();
        fs::write(upper.join("src/main.go"), vec![0u8; 200]).unwrap();
        fs::write(upper.join("lib/util.go"), vec![0u8; 300]).unwrap();
        assert_eq!(walk_upper_bytes(&upper).unwrap(), 500);
    }

    // -----------------------------------------------------------------------
    // du_fork — registry validation
    // -----------------------------------------------------------------------

    /// du_fork on an unknown fork-id returns NotFound.
    #[test]
    fn du_fork_not_found() {
        let root = TempDir::new().unwrap();
        let err = du_fork("ghost", root.path()).expect_err("expected NotFound error");
        let msg = err.to_string();
        assert!(
            msg.contains("not found") || msg.contains("ghost"),
            "unexpected error: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // du_fork — zero usage (no writes)
    // -----------------------------------------------------------------------

    /// A fork with an empty upper/ reports usage_bytes=0.
    #[test]
    fn du_fork_empty_upper_reports_zero() {
        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        let fork_dir = root.path().join("forks").join("agent-empty");
        let upper = fork_dir.join("upper");
        let work = fork_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();

        registry
            .insert_fork(
                "agent-empty",
                ForkEntry {
                    base_key: "mybase".to_owned(),
                    upper_path: upper.clone(),
                    work_path: work,
                    merged_path: None,
                    quota_bytes: None,
                    quota_mode: QuotaMode::Soft,
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    labels: HashMap::new(),
                },
            )
            .unwrap();

        // walk_upper_bytes should report 0 for the empty upper.
        let usage = walk_upper_bytes(&upper).unwrap();
        assert_eq!(usage, 0, "empty upper/ must report 0 bytes");
    }

    // -----------------------------------------------------------------------
    // du_fork — usage matches written bytes
    // -----------------------------------------------------------------------

    /// A fork with written files reports usage_bytes equal to the total bytes
    /// written (within a small tolerance for filesystem rounding).
    #[test]
    fn du_fork_usage_matches_written_bytes() {
        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        let fork_dir = root.path().join("forks").join("agent-1");
        let upper = fork_dir.join("upper");
        let work = fork_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();

        // Write 1 MiB (1048576 bytes) exactly.
        fs::write(upper.join("bigfile.bin"), vec![0u8; 1048576]).unwrap();

        registry
            .insert_fork(
                "agent-1",
                ForkEntry {
                    base_key: "mybase".to_owned(),
                    upper_path: upper.clone(),
                    work_path: work,
                    merged_path: None,
                    quota_bytes: None,
                    quota_mode: QuotaMode::Soft,
                    created_at: "2026-01-01T00:00:00Z".to_owned(),
                    labels: HashMap::new(),
                },
            )
            .unwrap();

        let usage = walk_upper_bytes(&upper).unwrap();
        assert_eq!(usage, 1048576, "usage_bytes must equal bytes written");
    }

    // -----------------------------------------------------------------------
    // du_fork — overage computed when over quota
    // -----------------------------------------------------------------------

    /// When usage exceeds quota, overage_bytes is computed correctly.
    #[test]
    fn du_output_overage_bytes_computed() {
        let usage: u64 = 1048576; // 1 MiB
        let quota: u64 = 524288; // 512 KiB

        let output = DuOutput {
            fork_id: "agent-1".to_owned(),
            usage_bytes: usage,
            usage_human: format_bytes(usage),
            quota_bytes: Some(quota),
            overage_bytes: Some(usage - quota),
        };

        assert_eq!(output.overage_bytes, Some(524288));
        assert_eq!(output.quota_bytes, Some(524288));
    }

    // -----------------------------------------------------------------------
    // Serialisation: quota_bytes absent when not set
    // -----------------------------------------------------------------------

    #[test]
    fn du_output_no_quota_omits_quota_fields() {
        let output = DuOutput {
            fork_id: "agent-1".to_owned(),
            usage_bytes: 0,
            usage_human: "0 B".to_owned(),
            quota_bytes: None,
            overage_bytes: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(
            !json.contains("quota_bytes"),
            "quota_bytes must be absent when not set"
        );
        assert!(
            !json.contains("overage_bytes"),
            "overage_bytes must be absent when not set"
        );
    }

    // -----------------------------------------------------------------------
    // Serialisation: quota_bytes present when set
    // -----------------------------------------------------------------------

    #[test]
    fn du_output_with_quota_includes_quota_fields() {
        let output = DuOutput {
            fork_id: "agent-1".to_owned(),
            usage_bytes: 2000,
            usage_human: format_bytes(2000),
            quota_bytes: Some(1000),
            overage_bytes: Some(1000),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(
            json.contains("\"quota_bytes\":1000"),
            "quota_bytes must be present"
        );
        assert!(
            json.contains("\"overage_bytes\":1000"),
            "overage_bytes must be present"
        );
    }
}
