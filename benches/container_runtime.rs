// benches/container_runtime.rs — Microbenchmark suite for ContainerRuntime backends.
//
// Canonical docs:
//   - docs/prd.md §5 (Guest Runtime)
//   - docs/architecture.md §Container Lifecycle
//   - Issue #113: ContainerRuntime trait and youki backend
//
// Measures per-operation latency (create/start/delete) for each backend.
// Results: p50/p95/p99 latency reported by criterion.
//
// Usage:
//   cargo bench                        # CrunBackend only
//   cargo bench --features youki       # CrunBackend + YoukiBackend
//
// NOTE: These benchmarks invoke real OCI runtime binaries and require:
//   - crun installed at /usr/bin/crun (for CrunBackend)
//   - CAP_SYS_ADMIN (for namespace operations) — for YoukiBackend (libcontainer)
//   - A minimal rootfs at /tmp/fastenv-bench-rootfs
//
// YoukiBackend uses libcontainer in-process — no youki binary in PATH needed.
//
// On CI or dev hosts without the above, the benchmarks skip gracefully.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use fastenv::container_runtime::{ContainerRuntime, CrunBackend};
use std::path::PathBuf;
use std::time::Duration;

/// Write a minimal OCI config.json into bundle_dir for benchmarking.
fn write_bench_config(bundle_dir: &std::path::Path, rootfs: &std::path::Path) {
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

/// Skip the benchmark group if prerequisites are not available.
fn prerequisites_available() -> bool {
    let rootfs = PathBuf::from("/tmp/fastenv-bench-rootfs");
    let crun = PathBuf::from("/usr/bin/crun");
    rootfs.exists() && crun.exists()
}

// ---------------------------------------------------------------------------
// CrunBackend microbenchmarks
// ---------------------------------------------------------------------------

fn bench_crun_create(c: &mut Criterion) {
    if !prerequisites_available() {
        eprintln!(
            "SKIP bench_crun_create: prerequisites not met \
             (need /usr/bin/crun and /tmp/fastenv-bench-rootfs)"
        );
        return;
    }

    let rootfs = PathBuf::from("/tmp/fastenv-bench-rootfs");
    let mut group = c.benchmark_group("crun/create");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function(BenchmarkId::new("create", "crun"), |b| {
        b.iter(|| {
            let tmp = tempfile::TempDir::new().unwrap();
            write_bench_config(tmp.path(), &rootfs);
            let backend = CrunBackend::default();
            backend.create("bench-fork", tmp.path()).unwrap();
        });
    });
    group.finish();
}

fn bench_crun_start(c: &mut Criterion) {
    if !prerequisites_available() {
        eprintln!(
            "SKIP bench_crun_start: prerequisites not met \
             (need /usr/bin/crun and /tmp/fastenv-bench-rootfs)"
        );
        return;
    }

    let rootfs = PathBuf::from("/tmp/fastenv-bench-rootfs");
    let mut group = c.benchmark_group("crun/start");
    group.measurement_time(Duration::from_secs(30));
    // Fewer samples because container start is expensive.
    group.sample_size(10);

    group.bench_function(BenchmarkId::new("start", "crun"), |b| {
        b.iter(|| {
            let tmp = tempfile::TempDir::new().unwrap();
            write_bench_config(tmp.path(), &rootfs);
            let fork_id = format!("bench-{}", std::process::id());
            let backend = CrunBackend::default();
            backend.create(&fork_id, tmp.path()).unwrap();
            let _exit_code = backend.start(&fork_id, tmp.path()).unwrap();
            backend.delete(&fork_id).unwrap();
        });
    });
    group.finish();
}

fn bench_crun_delete(c: &mut Criterion) {
    let mut group = c.benchmark_group("crun/delete");
    group.measurement_time(Duration::from_secs(5));

    // CrunBackend delete is a no-op, so this measures the tracing overhead.
    group.bench_function(BenchmarkId::new("delete", "crun"), |b| {
        b.iter(|| {
            let backend = CrunBackend::default();
            backend.delete("bench-fork").unwrap();
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// YoukiBackend microbenchmarks (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "youki")]
fn bench_youki_create(c: &mut Criterion) {
    use fastenv::container_runtime::YoukiBackend;

    if !prerequisites_available() {
        eprintln!(
            "SKIP bench_youki_create: prerequisites not met \
             (need CAP_SYS_ADMIN and /tmp/fastenv-bench-rootfs; no youki binary required)"
        );
        return;
    }

    let rootfs = PathBuf::from("/tmp/fastenv-bench-rootfs");
    let mut group = c.benchmark_group("youki/create");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function(BenchmarkId::new("create", "youki"), |b| {
        b.iter(|| {
            let tmp = tempfile::TempDir::new().unwrap();
            let state_tmp = tempfile::TempDir::new().unwrap();
            write_bench_config(tmp.path(), &rootfs);
            let backend = YoukiBackend::new(state_tmp.path());
            backend.create("bench-fork", tmp.path()).unwrap();
        });
    });
    group.finish();
}

#[cfg(feature = "youki")]
fn bench_youki_start(c: &mut Criterion) {
    use fastenv::container_runtime::YoukiBackend;

    if !prerequisites_available() {
        eprintln!(
            "SKIP bench_youki_start: prerequisites not met \
             (need CAP_SYS_ADMIN and /tmp/fastenv-bench-rootfs; no youki binary required)"
        );
        return;
    }

    let rootfs = PathBuf::from("/tmp/fastenv-bench-rootfs");
    let mut group = c.benchmark_group("youki/start");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    group.bench_function(BenchmarkId::new("start", "youki"), |b| {
        b.iter(|| {
            let tmp = tempfile::TempDir::new().unwrap();
            let state_tmp = tempfile::TempDir::new().unwrap();
            write_bench_config(tmp.path(), &rootfs);
            let fork_id = format!("bench-youki-{}", std::process::id());
            let backend = YoukiBackend::new(state_tmp.path());
            backend.create(&fork_id, tmp.path()).unwrap();
            let _exit_code = backend.start(&fork_id, tmp.path()).unwrap();
            backend.delete(&fork_id).unwrap();
        });
    });
    group.finish();
}

#[cfg(feature = "youki")]
fn bench_youki_delete(c: &mut Criterion) {
    use fastenv::container_runtime::YoukiBackend;

    let mut group = c.benchmark_group("youki/delete");
    group.measurement_time(Duration::from_secs(5));

    // YoukiBackend delete uses libcontainer in-process — no youki binary needed.
    // Deleting a non-existent container is best-effort and does not return an error.
    group.bench_function(BenchmarkId::new("delete", "youki"), |b| {
        b.iter(|| {
            let state_tmp = tempfile::TempDir::new().unwrap();
            let backend = YoukiBackend::new(state_tmp.path());
            let _ = backend.delete("bench-fork-nonexistent");
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion registration
// ---------------------------------------------------------------------------

#[cfg(not(feature = "youki"))]
criterion_group!(
    benches,
    bench_crun_create,
    bench_crun_start,
    bench_crun_delete,
);

#[cfg(feature = "youki")]
criterion_group!(
    benches,
    bench_crun_create,
    bench_crun_start,
    bench_crun_delete,
    bench_youki_create,
    bench_youki_start,
    bench_youki_delete,
);

criterion_main!(benches);
