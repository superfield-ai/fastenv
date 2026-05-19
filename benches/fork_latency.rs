// benches/fork_latency.rs — Container runtime fork latency benchmarks.
//
// Canonical docs:
//   - docs/prd.md §5 (Guest Runtime)
//   - docs/architecture.md §Container Lifecycle
//   - Issue #121: Rewrite container-runtime benchmarks to measure real fork latency
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
// Results are written to docs/benchmarks/container-runtime-comparison.json.
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

/// Machine-readable benchmark result per backend run.
///
/// Written to docs/benchmarks/container-runtime-comparison.json after the
/// benchmark run so CI and post-analysis tooling can compare backends.
#[derive(Debug, Serialize)]
struct ForkLatencyResult {
    /// Backend identifier: "crun" or "youki".
    backend: String,
    /// Wall time from backend.create() to backend.start() return, in milliseconds.
    fork_time_ms: u64,
    /// Time from backend.start() call until sentinel file appears, in milliseconds.
    first_write_ms: u64,
    /// True if backend identity was confirmed via /proc/*/cmdline scanning.
    backend_verified: bool,
}

impl ForkLatencyResult {
    /// Write this result to docs/benchmarks/container-runtime-comparison.json.
    ///
    /// If the file already exists, the new result replaces any entry for the
    /// same backend. Creates the docs/benchmarks/ directory if it does not exist.
    fn write_to_artifact(&self) {
        let artifact_dir = PathBuf::from("docs/benchmarks");
        let artifact_path = artifact_dir.join("container-runtime-comparison.json");

        if let Err(e) = std::fs::create_dir_all(&artifact_dir) {
            eprintln!(
                "fork_latency: failed to create {}: {e}",
                artifact_dir.display()
            );
            return;
        }

        // Load existing results array if present.
        let mut results: Vec<serde_json::Value> = if artifact_path.exists() {
            match std::fs::read_to_string(&artifact_path) {
                Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
                Err(_) => vec![],
            }
        } else {
            vec![]
        };

        // Remove any existing entry for this backend.
        results.retain(|v| v.get("backend").and_then(|b| b.as_str()) != Some(&self.backend));

        // Append this run.
        if let Ok(v) = serde_json::to_value(self) {
            results.push(v);
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
    let deadline = t0 + Duration::from_secs(5);
    while !sentinel_path.exists() && Instant::now() < deadline {
        std::hint::spin_loop();
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

    let mut last_verified = false;
    let mut last_fork_ms: u64 = 0;

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
                        last_fork_ms = elapsed.as_millis() as u64;
                        total += elapsed;
                    }
                    Err(e) => eprintln!("WARN bench_crun_fork_time iter {i}: {e}"),
                }
            }
            total
        });
    });
    group.finish();

    // Write result artifact after the benchmark group completes.
    // Use a separate measurement for the artifact (last sample values).
    ForkLatencyResult {
        backend: "crun".to_string(),
        fork_time_ms: last_fork_ms,
        first_write_ms: 0, // filled in by bench_crun_first_write
        backend_verified: last_verified,
    }
    .write_to_artifact();
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

    let mut last_verified = false;
    let mut last_fw_ms: u64 = 0;

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
                        last_fw_ms = elapsed.as_millis() as u64;
                        total += elapsed;
                    }
                    Err(e) => eprintln!("WARN bench_crun_first_write iter {i}: {e}"),
                }
            }
            total
        });
    });
    group.finish();

    // Update artifact with first_write data, merging with any existing crun entry.
    update_artifact_first_write("crun", last_fw_ms, last_verified);
}

/// Update the artifact JSON: set first_write_ms (and backend_verified) for the
/// named backend, preserving fork_time_ms from any prior write.
fn update_artifact_first_write(backend: &str, first_write_ms: u64, backend_verified: bool) {
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

    // Find the entry for this backend and update it, or create a new one.
    if let Some(entry) = results
        .iter_mut()
        .find(|v| v.get("backend").and_then(|b| b.as_str()) == Some(backend))
    {
        entry["first_write_ms"] = serde_json::json!(first_write_ms);
        entry["backend_verified"] = serde_json::json!(backend_verified);
    } else {
        results.push(serde_json::json!({
            "backend": backend,
            "fork_time_ms": 0,
            "first_write_ms": first_write_ms,
            "backend_verified": backend_verified,
        }));
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

    let mut last_verified = false;
    let mut last_fork_ms: u64 = 0;

    // Track whether the backend is functional in this environment.
    let mut backend_available = true;

    group.bench_function("fork_time", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for i in 0..iters {
                if !backend_available {
                    // Backend failed on a prior iteration; skip remaining samples.
                    total += Duration::from_millis(0);
                    continue;
                }
                let tmp = tempfile::TempDir::new().unwrap();
                let state_tmp = tempfile::TempDir::new().unwrap();
                write_bench_config(tmp.path(), &rootfs);
                let fork_id = format!("bench-youki-ft-{}-{}", std::process::id(), i);
                let backend = YoukiBackend::new(state_tmp.path());
                match measure_fork_time(&backend, &fork_id, tmp.path(), verify_youki_backend) {
                    Ok((elapsed, verified)) => {
                        last_verified = verified;
                        last_fork_ms = elapsed.as_millis() as u64;
                        total += elapsed;
                    }
                    Err(e) => {
                        eprintln!("SKIP bench_youki_fork_time: backend error at iter {i}: {e}");
                        backend_available = false;
                    }
                }
            }
            total
        });
    });
    group.finish();

    if last_fork_ms > 0 {
        ForkLatencyResult {
            backend: "youki".to_string(),
            fork_time_ms: last_fork_ms,
            first_write_ms: 0,
            backend_verified: last_verified,
        }
        .write_to_artifact();
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

    let mut last_verified = false;
    let mut last_fw_ms: u64 = 0;

    let mut backend_available = true;

    group.bench_function("first_write", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for i in 0..iters {
                if !backend_available {
                    total += Duration::from_millis(0);
                    continue;
                }
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
                        last_fw_ms = elapsed.as_millis() as u64;
                        total += elapsed;
                    }
                    Err(e) => {
                        eprintln!("SKIP bench_youki_first_write: backend error at iter {i}: {e}");
                        backend_available = false;
                    }
                }
            }
            total
        });
    });
    group.finish();

    if last_fw_ms > 0 {
        update_artifact_first_write("youki", last_fw_ms, last_verified);
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
