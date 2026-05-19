// benches/container_runtime.rs — Per-op container runtime microbenchmarks.
//
// Canonical docs:
//   - docs/prd.md §5 (Guest Runtime)
//   - docs/architecture.md §Container Lifecycle
//   - docs/benchmarks/README.md (JSON artifact schema)
//   - Issue #113: ContainerRuntime trait and youki backend
//   - Issue #124: Make crun-vs-youki benchmark signal trustworthy
//
// SCOPE — issue #124
// ------------------
// The previous incarnation of this file compared `crun/create`, `crun/delete`,
// `youki/create`, `youki/delete` head-to-head as if they measured equivalent
// work. They did not:
//
//   * `CrunBackend::create`   = "validate config.json exists" (essentially free)
//   * `YoukiBackend::create`  = full `libcontainer::ContainerBuilder::build()`,
//                                which forks an intermediate process and sets up
//                                namespaces.
//   * `CrunBackend::delete`   = no-op (the `crun run` invocation in `start`
//                                handles its own cleanup; this method only
//                                emits a tracing span).
//   * `YoukiBackend::delete`  = real `libcontainer::Container::delete(false)`.
//
// Publishing those side-by-side made it look like "youki is much slower at
// create/delete than crun", but the timed regions were structurally different
// — crun's work for create/delete simply lives elsewhere in its lifecycle.
//
// The only operation that times *equivalent work* across both backends is the
// full create+start+delete round-trip, and that is already covered by
// `benches/fork_latency.rs` (`fork_time` / `first_write`). To avoid republishing
// a misleading comparison, the per-op `create` and `delete` benchmarks have
// been removed from this file (issue #124 acceptance criterion). The per-op
// `start` benchmarks are kept because both backends do equivalent work there:
// each blocks until the container init process exits and returns its real
// exit code (see `YoukiBackend::start` in `src/container_runtime.rs`).
//
// Usage:
//   cargo bench --bench container_runtime                  # CrunBackend only
//   cargo bench --bench container_runtime --features youki # + YoukiBackend
//
// Prerequisites:
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
// CrunBackend microbenchmarks — only `start` (the comparable op).
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// YoukiBackend microbenchmarks (feature-gated) — only `start`.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Criterion registration
// ---------------------------------------------------------------------------

#[cfg(not(feature = "youki"))]
criterion_group!(benches, bench_crun_start);

#[cfg(feature = "youki")]
criterion_group!(benches, bench_crun_start, bench_youki_start);

criterion_main!(benches);
