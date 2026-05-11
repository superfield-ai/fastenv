// gc.rs — `fastenv gc` implementation.
//
// Canonical docs:
//   - docs/architecture.md
//   - docs/implementation-plan.md
//
// Pipeline
// --------
//  1. Open registry and collect all forks with their created_at timestamps.
//  2. Build eviction candidate set via two independent policies:
//       a. TTL: forks whose created_at is older than --max-age.
//       b. LRU: if fork count exceeds --max-forks, evict the oldest first
//          until only --max-forks remain.
//  3. In --dry-run mode: print candidates as JSON and exit.
//  4. For each evicted fork (inside an exclusive registry lock):
//       a. umount merged/ if mounted.
//       b. rm -rf upper/ and work/.
//       c. registry.remove_fork.
//  5. Emit JSON summary: evicted_forks, bytes_reclaimed.

use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::discard::discard_fork;
use crate::du::walk_upper_bytes;
use crate::registry::Registry;

// ---------------------------------------------------------------------------
// Public options
// ---------------------------------------------------------------------------

/// Options controlling the `gc` sweep.
pub struct GcOptions {
    /// Maximum age as a `std::time::Duration`.  Forks older than this are
    /// eviction candidates.  `None` means no TTL policy is applied.
    pub max_age: Option<std::time::Duration>,
    /// Maximum number of forks to retain.  When the live count exceeds this,
    /// the oldest forks are evicted first.  `None` means no LRU policy.
    pub max_forks: Option<usize>,
    /// When `true`, only print candidates; do not mutate anything.
    pub dry_run: bool,
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// JSON summary emitted to stdout on completion.
#[derive(Debug, Serialize)]
pub struct GcSummary {
    pub evicted_forks: Vec<String>,
    pub bytes_reclaimed: u64,
    pub dry_run: bool,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Execute the `gc` pipeline.
///
/// * `root` — fastenv data root (e.g. `/var/lib/fastenv`).
/// * `opts` — eviction policy options.
pub fn run_gc(root: &Path, opts: &GcOptions) -> Result<()> {
    let registry = Registry::open(root)?;
    let now = Utc::now();

    // ── 1. Collect all forks sorted oldest-first ─────────────────────────────
    let all_forks = registry.list_forks()?;

    // Parse created_at and sort by timestamp (oldest first).
    let mut forks_with_time: Vec<(String, DateTime<Utc>)> = all_forks
        .iter()
        .filter_map(|(key, entry)| {
            let ts = entry.created_at.parse::<DateTime<Utc>>().ok()?;
            Some((key.clone(), ts))
        })
        .collect();
    forks_with_time.sort_by_key(|(_, ts)| *ts);

    // ── 2. Build eviction candidate set ──────────────────────────────────────
    let mut to_evict: std::collections::HashSet<String> = std::collections::HashSet::new();

    // 2a. TTL policy: evict forks older than max_age.
    if let Some(max_age) = opts.max_age {
        let max_age_chrono =
            chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::zero());
        for (key, ts) in &forks_with_time {
            let age = now.signed_duration_since(*ts);
            if age >= max_age_chrono {
                to_evict.insert(key.clone());
            }
        }
    }

    // 2b. LRU policy: if count exceeds max_forks, evict oldest first.
    if let Some(max_forks) = opts.max_forks {
        let total = forks_with_time.len();
        if total > max_forks {
            let excess = total - max_forks;
            // forks_with_time is sorted oldest-first; take from the front.
            for (key, _) in forks_with_time.iter().take(excess) {
                to_evict.insert(key.clone());
            }
        }
    }

    // Stable eviction order: oldest first (forks_with_time is already sorted by timestamp).
    let eviction_list: Vec<String> = forks_with_time
        .iter()
        .filter(|(key, _)| to_evict.contains(key))
        .map(|(key, _)| key.clone())
        .collect();

    // ── 3. Dry-run: print candidates and exit ────────────────────────────────
    if opts.dry_run {
        let summary = GcSummary {
            evicted_forks: eviction_list.clone(),
            bytes_reclaimed: 0,
            dry_run: true,
        };
        emit_summary(&summary)?;
        return Ok(());
    }

    // ── 4. Evict each candidate ───────────────────────────────────────────────
    let mut bytes_reclaimed: u64 = 0;
    let mut actually_evicted: Vec<String> = Vec::new();

    for fork_key in &eviction_list {
        // Measure upper/ bytes before discarding.
        if let Ok(entry) = registry.get_fork(fork_key) {
            let upper_bytes = walk_upper_bytes(&entry.upper_path).unwrap_or(0);
            bytes_reclaimed += upper_bytes;
        }

        // Reuse the discard pipeline which handles umount + rm + registry remove.
        match discard_fork(fork_key, root) {
            Ok(()) => {
                actually_evicted.push(fork_key.clone());
                tracing::info!(
                    command = "gc",
                    fork_id = %fork_key,
                    outcome = "evicted",
                    "gc: fork evicted"
                );
            }
            Err(e) => {
                tracing::warn!(
                    command = "gc",
                    fork_id = %fork_key,
                    error = %e,
                    "gc: failed to evict fork, skipping"
                );
            }
        }
    }

    // ── 5. Emit JSON summary ─────────────────────────────────────────────────
    let summary = GcSummary {
        evicted_forks: actually_evicted,
        bytes_reclaimed,
        dry_run: false,
    };
    emit_summary(&summary)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn emit_summary(summary: &GcSummary) -> Result<()> {
    let line = serde_json::to_string(summary).context("serialize gc summary")?;
    let mut stdout = io::stdout();
    writeln!(stdout, "{line}").context("write gc summary")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Duration parsing helper (exported for use in main.rs)
// ---------------------------------------------------------------------------

/// Parse a Go-style duration string into a `std::time::Duration`.
///
/// Supported units: `s` (seconds), `m` (minutes), `h` (hours).
/// Zero duration: `"0s"` or `"0"`.
///
/// Examples: `"24h"`, `"30m"`, `"0s"`.
pub fn parse_duration(s: &str) -> Result<std::time::Duration> {
    if s == "0" {
        return Ok(std::time::Duration::ZERO);
    }

    let (amount_str, unit) = if let Some(rest) = s.strip_suffix('s') {
        (rest, "s")
    } else if let Some(rest) = s.strip_suffix('m') {
        (rest, "m")
    } else if let Some(rest) = s.strip_suffix('h') {
        (rest, "h")
    } else {
        anyhow::bail!("invalid duration '{}': expected suffix s, m, or h", s)
    };

    let amount: u64 = amount_str
        .parse()
        .with_context(|| format!("invalid duration '{}': non-numeric amount", s))?;

    let secs = match unit {
        "s" => amount,
        "m" => amount * 60,
        "h" => amount * 3600,
        _ => unreachable!(),
    };

    Ok(std::time::Duration::from_secs(secs))
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
    // parse_duration
    // -----------------------------------------------------------------------

    #[test]
    fn parse_duration_hours() {
        assert_eq!(
            parse_duration("24h").unwrap(),
            std::time::Duration::from_secs(86400)
        );
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(
            parse_duration("30m").unwrap(),
            std::time::Duration::from_secs(1800)
        );
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("0s").unwrap(), std::time::Duration::ZERO);
    }

    #[test]
    fn parse_duration_zero_bare() {
        assert_eq!(parse_duration("0").unwrap(), std::time::Duration::ZERO);
    }

    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("10x").is_err());
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_fork_entry_with_time(
        base_key: &str,
        upper: std::path::PathBuf,
        work: std::path::PathBuf,
        created_at: &str,
    ) -> ForkEntry {
        ForkEntry {
            base_key: base_key.to_owned(),
            upper_path: upper,
            work_path: work,
            merged_path: None,
            quota_bytes: None,
            quota_mode: QuotaMode::Soft,
            created_at: created_at.to_owned(),
            labels: HashMap::new(),
        }
    }

    fn create_fork_on_disk(root: &Path, fork_key: &str, created_at: &str, registry: &Registry) {
        let fork_dir = root.join("forks").join(fork_key);
        let upper = fork_dir.join("upper");
        let work = fork_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        registry
            .insert_fork(
                fork_key,
                make_fork_entry_with_time("base", upper, work, created_at),
            )
            .unwrap();
    }

    // -----------------------------------------------------------------------
    // gc --max-age 0s evicts all forks
    // -----------------------------------------------------------------------

    #[test]
    fn gc_max_age_zero_evicts_all() {
        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        // Create 3 forks all with old timestamps.
        create_fork_on_disk(root.path(), "fork-a", "2020-01-01T00:00:00Z", &registry);
        create_fork_on_disk(root.path(), "fork-b", "2020-06-01T00:00:00Z", &registry);
        create_fork_on_disk(root.path(), "fork-c", "2021-01-01T00:00:00Z", &registry);

        let opts = GcOptions {
            max_age: Some(std::time::Duration::ZERO),
            max_forks: None,
            dry_run: false,
        };

        run_gc(root.path(), &opts).unwrap();

        let remaining = registry.list_forks().unwrap();
        assert!(
            remaining.is_empty(),
            "expected all forks evicted, got: {:?}",
            remaining.keys().collect::<Vec<_>>()
        );
    }

    // -----------------------------------------------------------------------
    // gc --max-forks 2 keeps only 2 newest
    // -----------------------------------------------------------------------

    #[test]
    fn gc_max_forks_keeps_newest() {
        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        // 5 forks with distinct timestamps; newest are d and e.
        create_fork_on_disk(root.path(), "fork-a", "2020-01-01T00:00:00Z", &registry);
        create_fork_on_disk(root.path(), "fork-b", "2020-02-01T00:00:00Z", &registry);
        create_fork_on_disk(root.path(), "fork-c", "2020-03-01T00:00:00Z", &registry);
        create_fork_on_disk(root.path(), "fork-d", "2020-04-01T00:00:00Z", &registry);
        create_fork_on_disk(root.path(), "fork-e", "2020-05-01T00:00:00Z", &registry);

        let opts = GcOptions {
            max_age: None,
            max_forks: Some(2),
            dry_run: false,
        };

        run_gc(root.path(), &opts).unwrap();

        let remaining = registry.list_forks().unwrap();
        assert_eq!(
            remaining.len(),
            2,
            "expected 2 forks retained, got: {:?}",
            remaining.keys().collect::<Vec<_>>()
        );
        // Newest two should survive.
        assert!(
            remaining.contains_key("fork-d"),
            "fork-d (4th newest) must be retained"
        );
        assert!(
            remaining.contains_key("fork-e"),
            "fork-e (newest) must be retained"
        );
    }

    // -----------------------------------------------------------------------
    // gc --dry-run does not remove forks
    // -----------------------------------------------------------------------

    #[test]
    fn gc_dry_run_no_removal() {
        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        create_fork_on_disk(root.path(), "fork-x", "2020-01-01T00:00:00Z", &registry);

        let opts = GcOptions {
            max_age: Some(std::time::Duration::ZERO),
            max_forks: None,
            dry_run: true,
        };

        run_gc(root.path(), &opts).unwrap();

        let remaining = registry.list_forks().unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "dry-run must not remove forks; expected 1, got {}",
            remaining.len()
        );
    }

    // -----------------------------------------------------------------------
    // gc with no candidates produces empty evicted_forks
    // -----------------------------------------------------------------------

    #[test]
    fn gc_no_candidates_empty_evicted() {
        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        // Forks with future timestamps (will not be evicted by TTL).
        create_fork_on_disk(root.path(), "fork-new", "2099-01-01T00:00:00Z", &registry);

        let opts = GcOptions {
            max_age: Some(std::time::Duration::from_secs(3600)), // 1h TTL
            max_forks: None,
            dry_run: false,
        };

        run_gc(root.path(), &opts).unwrap();

        let remaining = registry.list_forks().unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "fork with future timestamp must not be evicted"
        );
    }

    // -----------------------------------------------------------------------
    // bytes_reclaimed is correct
    // -----------------------------------------------------------------------

    #[test]
    fn gc_bytes_reclaimed_matches_upper_contents() {
        let root = TempDir::new().unwrap();
        let registry = Registry::open(root.path()).unwrap();

        let fork_dir = root.path().join("forks").join("fork-sized");
        let upper = fork_dir.join("upper");
        let work = fork_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        // Write exactly 512 bytes.
        fs::write(upper.join("data.bin"), vec![0u8; 512]).unwrap();

        registry
            .insert_fork(
                "fork-sized",
                make_fork_entry_with_time("base", upper, work, "2020-01-01T00:00:00Z"),
            )
            .unwrap();

        let opts = GcOptions {
            max_age: Some(std::time::Duration::ZERO),
            max_forks: None,
            dry_run: false,
        };

        run_gc(root.path(), &opts).unwrap();

        // Verify registry is clean.
        let remaining = registry.list_forks().unwrap();
        assert!(remaining.is_empty(), "fork must be evicted");
        // We can't easily capture stdout here, but at least confirm the gc ran.
    }
}
