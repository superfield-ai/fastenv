// bench.rs — `fastenv bench --base <key> [--iterations N] [--exec]` implementation.
//
// Canonical docs:
//   - docs/architecture.md
//   - docs/implementation-plan.md
//
// Pipeline
// --------
//  1. Validate that the base snapshot exists in the registry.
//  2. Run N fork+discard iterations; measure wall-clock of fork() per iteration.
//  3. Emit a progress line to stderr every 10 iterations.
//  4. If --exec: run N exec-latency iterations (fork → exec /bin/true → discard).
//  5. Compute p50/p95/p99 from the latency samples.
//  6. Clean up ALL forks created during the run (even on early error).
//  7. Emit a single JSON document to stdout.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::discard::discard_fork;
use crate::fork::fork_base;
use crate::registry::Registry;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Options for the bench subcommand.
pub struct BenchOptions {
    /// Number of fork+discard iterations to run.
    pub iterations: u32,
    /// Whether to measure exec latency in addition to fork latency.
    pub measure_exec: bool,
}

/// Top-level JSON output of the bench subcommand.
#[derive(Serialize)]
pub struct BenchResult {
    /// Number of iterations performed.
    pub iterations: u32,
    /// Median fork latency in milliseconds.
    pub fork_p50_ms: f64,
    /// 95th-percentile fork latency in milliseconds.
    pub fork_p95_ms: f64,
    /// 99th-percentile fork latency in milliseconds.
    pub fork_p99_ms: f64,
    /// Median exec latency in milliseconds (only present when --exec is given).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_p50_ms: Option<f64>,
    /// 95th-percentile exec latency in milliseconds (only present when --exec is given).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_p95_ms: Option<f64>,
    /// 99th-percentile exec latency in milliseconds (only present when --exec is given).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_p99_ms: Option<f64>,
    /// Whether fork_p95_ms meets the ≤ 100ms product budget.
    pub meets_budget_p95: bool,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the bench suite and return structured results.
///
/// * `base_key`  — name of the base snapshot to fork from.
/// * `root`      — fastenv data root (e.g. `/var/lib/fastenv`).
/// * `opts`      — benchmark options (iterations, exec flag).
///
/// On success all temporary forks created during the run have been discarded.
pub fn run_bench(base_key: &str, root: &Path, opts: &BenchOptions) -> Result<BenchResult> {
    // ── 1. Validate base exists ───────────────────────────────────────────────
    {
        let registry = Registry::open(root)?;
        let bases = registry.list_bases().context("listing bases")?;
        if !bases.contains_key(base_key) {
            bail!(
                "base '{}' not found: run 'fastenv build-base' first",
                base_key
            );
        }
    }

    // ── 2. Fork latency iterations ────────────────────────────────────────────
    let mut fork_samples: Vec<f64> = Vec::with_capacity(opts.iterations as usize);

    for i in 0..opts.iterations {
        // Progress line to stderr every 10 iterations.
        if i % 10 == 0 {
            eprint!("bench: fork iteration {}/{}\r", i + 1, opts.iterations);
            let _ = std::io::stderr().flush();
        }

        let fork_id = format!("bench-fork-{}-{}", i, nanos_now());

        // Measure wall-clock of the fork() call only.
        let t0 = Instant::now();
        fork_base(base_key, &fork_id, root, None)?;
        let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;

        fork_samples.push(elapsed_ms);

        // Discard immediately; accumulate any error after the loop.
        discard_fork(&fork_id, root).with_context(|| {
            format!(
                "bench: cleanup fork '{}' after fork latency measurement",
                fork_id
            )
        })?;
    }

    // Clear the progress line.
    eprintln!(
        "bench: fork iterations complete ({} samples)        ",
        opts.iterations
    );

    // ── 3. Exec latency iterations (optional) ─────────────────────────────────
    let exec_stats: Option<(f64, f64, f64)> = if opts.measure_exec {
        let mut exec_samples: Vec<f64> = Vec::with_capacity(opts.iterations as usize);

        for i in 0..opts.iterations {
            if i % 10 == 0 {
                eprint!("bench: exec iteration {}/{}\r", i + 1, opts.iterations);
                let _ = std::io::stderr().flush();
            }

            let fork_id = format!("bench-exec-{}-{}", i, nanos_now());

            // Create the fork, then time exec of a no-op command.
            fork_base(base_key, &fork_id, root, None)?;

            let t0 = Instant::now();
            let status = Command::new("fastenv")
                .args(["exec", &fork_id, "--", "/bin/true"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .or_else(|_| {
                    // Fall back to self (argv[0]) if "fastenv" is not on PATH.
                    Command::new(std::env::current_exe().unwrap_or_else(|_| "fastenv".into()))
                        .args(["exec", &fork_id, "--", "/bin/true"])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                })
                .context("bench: spawn fastenv exec for exec latency measurement")?;
            let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;

            // Discard regardless of exec exit code.
            discard_fork(&fork_id, root).with_context(|| {
                format!(
                    "bench: cleanup fork '{}' after exec latency measurement",
                    fork_id
                )
            })?;

            if status.success() {
                exec_samples.push(elapsed_ms);
            }
        }

        eprintln!(
            "bench: exec iterations complete ({} samples)        ",
            exec_samples.len()
        );

        if exec_samples.is_empty() {
            None
        } else {
            let p50 = percentile(&mut exec_samples, 50.0);
            let p95 = percentile(&mut exec_samples, 95.0);
            let p99 = percentile(&mut exec_samples, 99.0);
            Some((p50, p95, p99))
        }
    } else {
        None
    };

    // ── 4. Compute fork percentiles ───────────────────────────────────────────
    let fork_p50 = percentile(&mut fork_samples, 50.0);
    let fork_p95 = percentile(&mut fork_samples, 95.0);
    let fork_p99 = percentile(&mut fork_samples, 99.0);

    Ok(BenchResult {
        iterations: opts.iterations,
        fork_p50_ms: fork_p50,
        fork_p95_ms: fork_p95,
        fork_p99_ms: fork_p99,
        exec_p50_ms: exec_stats.map(|(p50, _, _)| p50),
        exec_p95_ms: exec_stats.map(|(_, p95, _)| p95),
        exec_p99_ms: exec_stats.map(|(_, _, p99)| p99),
        meets_budget_p95: fork_p95 <= 100.0,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the current monotonic time in nanoseconds (for unique fork IDs).
fn nanos_now() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

/// Compute the p-th percentile of `samples` using linear interpolation.
/// Sorts `samples` in place.
fn percentile(samples: &mut [f64], p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if samples.len() == 1 {
        return samples[0];
    }

    let rank = (p / 100.0) * (samples.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;

    if lower == upper {
        samples[lower]
    } else {
        let frac = rank - lower as f64;
        samples[lower] * (1.0 - frac) + samples[upper] * frac
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_single_element() {
        let mut v = vec![42.0];
        assert_eq!(percentile(&mut v, 50.0), 42.0);
        assert_eq!(percentile(&mut v, 95.0), 42.0);
        assert_eq!(percentile(&mut v, 99.0), 42.0);
    }

    #[test]
    fn percentile_two_elements() {
        let mut v = vec![10.0, 20.0];
        // p50 = midpoint
        let p50 = percentile(&mut v.clone(), 50.0);
        assert!((p50 - 15.0).abs() < 1e-9, "p50 = {p50}");
        // p0 = min, p100 = max
        assert_eq!(percentile(&mut v.clone(), 0.0), 10.0);
        assert_eq!(percentile(&mut v, 100.0), 20.0);
    }

    #[test]
    fn percentile_sorted_result() {
        let mut v = vec![5.0, 1.0, 3.0, 2.0, 4.0];
        let p50 = percentile(&mut v, 50.0);
        // median of [1,2,3,4,5] = 3.0
        assert!((p50 - 3.0).abs() < 1e-9, "p50 = {p50}");
    }

    #[test]
    fn percentile_empty_returns_zero() {
        let mut v: Vec<f64> = vec![];
        assert_eq!(percentile(&mut v, 50.0), 0.0);
    }

    #[test]
    fn bench_result_json_fork_fields() {
        let result = BenchResult {
            iterations: 20,
            fork_p50_ms: 12.3,
            fork_p95_ms: 45.6,
            fork_p99_ms: 78.9,
            exec_p50_ms: None,
            exec_p95_ms: None,
            exec_p99_ms: None,
            meets_budget_p95: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        let m: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(m["iterations"], 20);
        assert!((m["fork_p50_ms"].as_f64().unwrap() - 12.3).abs() < 1e-9);
        assert!((m["fork_p95_ms"].as_f64().unwrap() - 45.6).abs() < 1e-9);
        assert!((m["fork_p99_ms"].as_f64().unwrap() - 78.9).abs() < 1e-9);
        // exec fields must be absent when None
        assert!(m
            .get("exec_p50_ms")
            .map_or(true, |v| v.is_null() || v == &serde_json::Value::Null));
        assert!(m["meets_budget_p95"].as_bool().unwrap());
    }

    #[test]
    fn bench_result_json_exec_fields_present_when_some() {
        let result = BenchResult {
            iterations: 10,
            fork_p50_ms: 5.0,
            fork_p95_ms: 8.0,
            fork_p99_ms: 10.0,
            exec_p50_ms: Some(20.0),
            exec_p95_ms: Some(35.0),
            exec_p99_ms: Some(50.0),
            meets_budget_p95: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        let m: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            m.get("exec_p50_ms").is_some(),
            "exec_p50_ms should be present"
        );
        assert!((m["exec_p50_ms"].as_f64().unwrap() - 20.0).abs() < 1e-9);
    }

    #[test]
    fn bench_result_meets_budget_false_when_p95_exceeds_100() {
        let result = BenchResult {
            iterations: 5,
            fork_p50_ms: 90.0,
            fork_p95_ms: 150.0,
            fork_p99_ms: 200.0,
            exec_p50_ms: None,
            exec_p95_ms: None,
            exec_p99_ms: None,
            meets_budget_p95: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        let m: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(!m["meets_budget_p95"].as_bool().unwrap());
    }
}
