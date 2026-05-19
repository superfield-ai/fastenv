// benches/fork_latency.rs — Container runtime fork latency benchmarks.
//
// Canonical docs:
//   - docs/prd.md §5 (Guest Runtime)
//   - docs/architecture.md §Container Lifecycle
//   - docs/benchmarks/README.md (JSON artifact schema)
//   - Issue #121: Rewrite container-runtime benchmarks to measure real fork latency
//   - Issue #124: Make crun-vs-youki benchmark signal trustworthy
//
// Measures real container lifecycle latency for each backend:
//   1. fork_time:    Wall time from backend.create() to backend.start() return.
//                   Uses /bin/true as the workload (exits immediately).
//                   Isolates pure startup overhead.
//   2. first_write:  Time from backend.start() call until a sentinel file
//                   appears on the host (bind-mounted /output dir).
//                   Measures time-to-usable from the host's perspective.
//
// After each sample, backend identity is verified by scanning /proc/*/cmdline.
// Per-sample durations are aggregated and written as p50/p95/p99/min/max/stddev
// to docs/benchmarks/container-runtime-comparison.json (issue #124 — single
// per-backend single-last-sample fields (the old last_* keys) have been removed because
// any single outlier would otherwise define the published number).
//
// Usage:
//   cargo bench --bench fork_latency                    # CrunBackend only
//   cargo bench --bench fork_latency --features youki   # + YoukiBackend
//
// Prerequisites:
//   - /usr/bin/crun installed
//   - /tmp/fastenv-bench-rootfs populated (busybox-static rootfs)
//   - CAP_SYS_ADMIN (for namespace operations)

use criterion::{criterion_group, criterion_main, Criterion};
use fastenv::container_runtime::{ContainerRuntime, CrunBackend};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Result schema — written to docs/benchmarks/container-runtime-comparison.json
// ---------------------------------------------------------------------------

/// Per-metric percentile summary (issue #124).
///
/// All times are in milliseconds. The published JSON artifact carries one of
/// these per (backend, metric) pair (e.g. crun/fork_time, youki/first_write),
/// so consumers can defensibly compare backends at p95 from a single CI run.
#[derive(Debug, Serialize)]
struct MetricSummary {
    /// Number of successful samples that contributed to the percentiles.
    n: usize,
    p50_ms: u64,
    p95_ms: u64,
    p99_ms: u64,
    min_ms: u64,
    max_ms: u64,
    stddev_ms: u64,
}

impl MetricSummary {
    /// Build a summary from a vector of per-iteration durations. Returns `None`
    /// if no successful samples were collected (so the artifact does not carry
    /// fabricated zero values — see issue #124's "fail loud" requirement).
    fn from_samples(samples: &[Duration]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let mut ms: Vec<u64> = samples.iter().map(|d| d.as_millis() as u64).collect();
        ms.sort_unstable();
        let n = ms.len();
        let pick = |q: f64| -> u64 {
            // Nearest-rank percentile on the sorted vector. Clamp the index to
            // the last element so q=1.0 maps to max.
            let idx = ((q * n as f64).ceil() as usize)
                .saturating_sub(1)
                .min(n - 1);
            ms[idx]
        };
        let min_ms = *ms.first().unwrap();
        let max_ms = *ms.last().unwrap();
        let mean = ms.iter().sum::<u64>() as f64 / n as f64;
        let var = ms
            .iter()
            .map(|&v| {
                let d = v as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / n as f64;
        let stddev_ms = var.sqrt() as u64;
        Some(MetricSummary {
            n,
            p50_ms: pick(0.50),
            p95_ms: pick(0.95),
            p99_ms: pick(0.99),
            min_ms,
            max_ms,
            stddev_ms,
        })
    }
}

/// Update the artifact JSON for a given (backend, metric) pair. Existing keys
/// for other metrics on the same backend (and other backends entirely) are
/// preserved so successive benchmark functions can merge into one file.
fn write_metric_to_artifact(
    backend: &str,
    metric_key: &str,
    summary: &MetricSummary,
    backend_verified: bool,
) {
    let artifact_dir = PathBuf::from("docs/benchmarks");
    let artifact_path = artifact_dir.join("container-runtime-comparison.json");

    if let Err(e) = std::fs::create_dir_all(&artifact_dir) {
        eprintln!(
            "fork_latency: failed to create {}: {e}",
            artifact_dir.display()
        );
        return;
    }

    let mut results: Vec<serde_json::Value> = if artifact_path.exists() {
        match std::fs::read_to_string(&artifact_path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => vec![],
        }
    } else {
        vec![]
    };

    let summary_value = serde_json::to_value(summary).unwrap_or(serde_json::Value::Null);

    if let Some(entry) = results
        .iter_mut()
        .find(|v| v.get("backend").and_then(|b| b.as_str()) == Some(backend))
    {
        entry[metric_key] = summary_value;
        entry["backend_verified"] = serde_json::json!(backend_verified);
    } else {
        let mut obj = serde_json::Map::new();
        obj.insert("backend".to_string(), serde_json::json!(backend));
        obj.insert(metric_key.to_string(), summary_value);
        obj.insert(
            "backend_verified".to_string(),
            serde_json::json!(backend_verified),
        );
        results.push(serde_json::Value::Object(obj));
    }

    match serde_json::to_string_pretty(&results) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&artifact_path, json) {
                eprintln!(
                    "fork_latency: failed to write {}: {e}",
                    artifact_path.display()
                );
            }
        }
        Err(e) => eprintln!("fork_latency: failed to serialise results: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Prerequisites check
// ---------------------------------------------------------------------------

/// Returns true if the required prerequisites are present.
fn prerequisites_available() -> bool {
    let rootfs = PathBuf::from("/tmp/fastenv-bench-rootfs");
    let crun = PathBuf::from("/usr/bin/crun");
    rootfs.exists() && crun.exists()
}

// ---------------------------------------------------------------------------
// OCI config helpers
// ---------------------------------------------------------------------------

/// Write a minimal OCI config.json for a /bin/true workload into bundle_dir.
fn write_bench_config(bundle_dir: &Path, rootfs: &Path) {
    let config = serde_json::json!({
        "ociVersion": "1.0.0",
        "process": {
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "cwd": "/"
        },
        "root": {"path": rootfs.to_str().unwrap(), "readonly": false},
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
            {"destination": "/sys", "type": "sysfs", "source": "sysfs",
             "options": ["nosuid", "noexec", "nodev", "ro"]}
        ],
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "mount"}
            ]
        }
    });
    std::fs::write(
        bundle_dir.join("config.json"),
        serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();
}

/// Write an OCI config.json that bind-mounts output_dir as /output and runs
/// a shell command to write a sentinel file, into bundle_dir.
fn write_first_write_config(bundle_dir: &Path, rootfs: &Path, output_dir: &Path) {
    let config = serde_json::json!({
        "ociVersion": "1.0.0",
        "process": {
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/sh", "-c", "echo ready > /output/sentinel"],
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "cwd": "/"
        },
        "root": {"path": rootfs.to_str().unwrap(), "readonly": false},
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
            {"destination": "/sys", "type": "sysfs", "source": "sysfs",
             "options": ["nosuid", "noexec", "nodev", "ro"]},
            {
                "destination": "/output",
                "type": "bind",
                "source": output_dir.to_str().unwrap(),
                "options": ["bind", "rw"]
            }
        ],
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "mount"}
            ]
        }
    });
    std::fs::write(
        bundle_dir.join("config.json"),
        serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// Backend identity verification
// ---------------------------------------------------------------------------

/// Check that crun appears in /proc/*/cmdline (verifies CrunBackend called crun).
fn verify_crun_backend() -> bool {
    proc_cmdlines_contain("crun")
}

/// Check that no process with "crun" in its cmdline exists (verifies YoukiBackend
/// did not spawn crun).
#[cfg(feature = "youki")]
fn verify_youki_backend() -> bool {
    !proc_cmdlines_contain("crun")
}

/// Returns true if any process in /proc has "needle" in its cmdline.
fn proc_cmdlines_contain(needle: &str) -> bool {
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in proc_dir.flatten() {
        let cmdline_path = entry.path().join("cmdline");
        if let Ok(bytes) = std::fs::read(&cmdline_path) {
            // cmdline is NUL-separated; treat as a flat byte string for the search.
            if bytes
                .split(|&b| b == 0)
                .any(|arg| std::str::from_utf8(arg).is_ok_and(|s| s.contains(needle)))
            {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Measurement helpers
// ---------------------------------------------------------------------------

/// Measure fork_time: wall time from create() to start() return using /bin/true.
/// Returns Ok((duration, backend_verified)) or Err on backend failure.
fn measure_fork_time<R: ContainerRuntime>(
    backend: &R,
    fork_id: &str,
    bundle_dir: &Path,
    verify_fn: fn() -> bool,
) -> anyhow::Result<(Duration, bool)> {
    let t0 = Instant::now();
    backend.create(fork_id, bundle_dir)?;
    let _exit = backend.start(fork_id, bundle_dir)?;
    let elapsed = t0.elapsed();
    let verified = verify_fn();
    let _ = backend.delete(fork_id);
    Ok((elapsed, verified))
}

/// Measure first_write: time from start() call until sentinel file exists on host.
/// Returns Ok((duration, backend_verified)) or Err on backend failure.
fn measure_first_write<R: ContainerRuntime>(
    backend: &R,
    fork_id: &str,
    bundle_dir: &Path,
    sentinel_path: &Path,
    verify_fn: fn() -> bool,
) -> anyhow::Result<(Duration, bool)> {
    // Remove sentinel if it exists from a previous run.
    let _ = std::fs::remove_file(sentinel_path);

    backend.create(fork_id, bundle_dir)?;
    let t0 = Instant::now();
    // start() blocks until the container process exits; sentinel should exist after.
    let _exit = backend.start(fork_id, bundle_dir)?;
    // Poll until the sentinel file appears (should be immediate after start() returns).
    // Issue #124: sleep-based poll, not busy-wait. A tight busy-wait here would
    // steal a CPU from the container being timed and contaminate the
    // first_write measurement.
    let deadline = t0 + Duration::from_secs(5);
    while !sentinel_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_micros(50));
    }
    let elapsed = t0.elapsed();
    let verified = verify_fn();
    let _ = backend.delete(fork_id);
    Ok((elapsed, verified))
}

// ---------------------------------------------------------------------------
// CrunBackend fork_time benchmark
// ---------------------------------------------------------------------------

fn bench_crun_fork_time(c: &mut Criterion) {
    if !prerequisites_available() {
        eprintln!(
            "SKIP bench_crun_fork_time: prerequisites not met \
             (need /usr/bin/crun and /tmp/fastenv-bench-rootfs)"
        );
        return;
    }

    let rootfs = PathBuf::from("/tmp/fastenv-bench-rootfs");
    let mut group = c.benchmark_group("crun/fork_time");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(30));

    // Per-iteration durations across all criterion samples — feeds the
    // percentile summary written to the JSON artifact (issue #124).
    let mut all_samples: Vec<Duration> = Vec::new();
    let mut last_verified = false;

    group.bench_function("fork_time", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for i in 0..iters {
                let tmp = tempfile::TempDir::new().unwrap();
                write_bench_config(tmp.path(), &rootfs);
                let fork_id = format!("bench-crun-ft-{}-{}", std::process::id(), i);
                let backend = CrunBackend::default();
                match measure_fork_time(&backend, &fork_id, tmp.path(), verify_crun_backend) {
                    Ok((elapsed, verified)) => {
                        last_verified = verified;
                        all_samples.push(elapsed);
                        total += elapsed;
                    }
                    Err(e) => eprintln!("WARN bench_crun_fork_time iter {i}: {e}"),
                }
            }
            total
        });
    });
    group.finish();

    if let Some(summary) = MetricSummary::from_samples(&all_samples) {
        write_metric_to_artifact("crun", "fork_time", &summary, last_verified);
    } else {
        eprintln!("bench_crun_fork_time: no successful samples; artifact not updated");
    }
}

// ---------------------------------------------------------------------------
// CrunBackend first_write benchmark
// ---------------------------------------------------------------------------

fn bench_crun_first_write(c: &mut Criterion) {
    if !prerequisites_available() {
        eprintln!(
            "SKIP bench_crun_first_write: prerequisites not met \
             (need /usr/bin/crun and /tmp/fastenv-bench-rootfs)"
        );
        return;
    }

    let rootfs = PathBuf::from("/tmp/fastenv-bench-rootfs");
    let mut group = c.benchmark_group("crun/first_write");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    let mut all_samples: Vec<Duration> = Vec::new();
    let mut last_verified = false;

    group.bench_function("first_write", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for i in 0..iters {
                let bundle_tmp = tempfile::TempDir::new().unwrap();
                let output_tmp = tempfile::TempDir::new().unwrap();
                let sentinel = output_tmp.path().join("sentinel");
                write_first_write_config(bundle_tmp.path(), &rootfs, output_tmp.path());
                let fork_id = format!("bench-crun-fw-{}-{}", std::process::id(), i);
                let backend = CrunBackend::default();
                match measure_first_write(
                    &backend,
                    &fork_id,
                    bundle_tmp.path(),
                    &sentinel,
                    verify_crun_backend,
                ) {
                    Ok((elapsed, verified)) => {
                        last_verified = verified;
                        all_samples.push(elapsed);
                        total += elapsed;
                    }
                    Err(e) => eprintln!("WARN bench_crun_first_write iter {i}: {e}"),
                }
            }
            total
        });
    });
    group.finish();

    if let Some(summary) = MetricSummary::from_samples(&all_samples) {
        write_metric_to_artifact("crun", "first_write", &summary, last_verified);
    } else {
        eprintln!("bench_crun_first_write: no successful samples; artifact not updated");
    }
}

// ---------------------------------------------------------------------------
// YoukiBackend benchmarks (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "youki")]
fn bench_youki_fork_time(c: &mut Criterion) {
    use fastenv::container_runtime::YoukiBackend;

    if !prerequisites_available() {
        eprintln!(
            "SKIP bench_youki_fork_time: prerequisites not met \
             (need CAP_SYS_ADMIN and /tmp/fastenv-bench-rootfs; no youki binary required)"
        );
        return;
    }

    let rootfs = PathBuf::from("/tmp/fastenv-bench-rootfs");
    let mut group = c.benchmark_group("youki/fork_time");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(30));

    let mut all_samples: Vec<Duration> = Vec::new();
    let mut last_verified = false;
    // Issue #124: do NOT short-circuit failed iterations with a zero-duration
    // accumulator — that quietly drags the mean down and lets a partial youki
    // failure look like a youki win. Instead, panic so the workflow fails.
    let mut first_error: Option<String> = None;

    group.bench_function("fork_time", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for i in 0..iters {
                let tmp = tempfile::TempDir::new().unwrap();
                let state_tmp = tempfile::TempDir::new().unwrap();
                write_bench_config(tmp.path(), &rootfs);
                let fork_id = format!("bench-youki-ft-{}-{}", std::process::id(), i);
                let backend = YoukiBackend::new(state_tmp.path());
                match measure_fork_time(&backend, &fork_id, tmp.path(), verify_youki_backend) {
                    Ok((elapsed, verified)) => {
                        last_verified = verified;
                        all_samples.push(elapsed);
                        total += elapsed;
                    }
                    Err(e) => {
                        first_error.get_or_insert_with(|| format!("iter {i}: {e}"));
                        // Abort iteration sampling — failing loud is the point.
                        break;
                    }
                }
            }
            total
        });
    });
    group.finish();

    if let Some(err) = first_error {
        // Issue #124 fail-loud requirement: a youki iteration error must fail
        // the workflow, not silently produce a fake youki win.
        panic!("bench_youki_fork_time: youki iteration failed: {err}");
    }

    if let Some(summary) = MetricSummary::from_samples(&all_samples) {
        write_metric_to_artifact("youki", "fork_time", &summary, last_verified);
    } else {
        eprintln!("bench_youki_fork_time: no successful samples; artifact not updated");
    }
}

#[cfg(feature = "youki")]
fn bench_youki_first_write(c: &mut Criterion) {
    use fastenv::container_runtime::YoukiBackend;

    if !prerequisites_available() {
        eprintln!(
            "SKIP bench_youki_first_write: prerequisites not met \
             (need CAP_SYS_ADMIN and /tmp/fastenv-bench-rootfs; no youki binary required)"
        );
        return;
    }

    let rootfs = PathBuf::from("/tmp/fastenv-bench-rootfs");
    let mut group = c.benchmark_group("youki/first_write");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    let mut all_samples: Vec<Duration> = Vec::new();
    let mut last_verified = false;
    let mut first_error: Option<String> = None;

    group.bench_function("first_write", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for i in 0..iters {
                let bundle_tmp = tempfile::TempDir::new().unwrap();
                let output_tmp = tempfile::TempDir::new().unwrap();
                let state_tmp = tempfile::TempDir::new().unwrap();
                let sentinel = output_tmp.path().join("sentinel");
                write_first_write_config(bundle_tmp.path(), &rootfs, output_tmp.path());
                let fork_id = format!("bench-youki-fw-{}-{}", std::process::id(), i);
                let backend = YoukiBackend::new(state_tmp.path());
                match measure_first_write(
                    &backend,
                    &fork_id,
                    bundle_tmp.path(),
                    &sentinel,
                    verify_youki_backend,
                ) {
                    Ok((elapsed, verified)) => {
                        last_verified = verified;
                        all_samples.push(elapsed);
                        total += elapsed;
                    }
                    Err(e) => {
                        first_error.get_or_insert_with(|| format!("iter {i}: {e}"));
                        break;
                    }
                }
            }
            total
        });
    });
    group.finish();

    if let Some(err) = first_error {
        panic!("bench_youki_first_write: youki iteration failed: {err}");
    }

    if let Some(summary) = MetricSummary::from_samples(&all_samples) {
        write_metric_to_artifact("youki", "first_write", &summary, last_verified);
    } else {
        eprintln!("bench_youki_first_write: no successful samples; artifact not updated");
    }
}

// ---------------------------------------------------------------------------
// Criterion registration
// ---------------------------------------------------------------------------

#[cfg(not(feature = "youki"))]
criterion_group!(benches, bench_crun_fork_time, bench_crun_first_write);

#[cfg(feature = "youki")]
criterion_group!(
    benches,
    bench_crun_fork_time,
    bench_crun_first_write,
    bench_youki_fork_time,
    bench_youki_first_write,
);

criterion_main!(benches);
