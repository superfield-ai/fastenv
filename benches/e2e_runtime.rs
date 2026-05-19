// benches/e2e_runtime.rs — TOMBSTONE
//
// This file is intentionally empty. The E2E benchmark suite has been replaced
// by benches/fork_latency.rs, which measures real container lifecycle latency
// (fork_time and first_write) against actual OCI runtime backends.
//
// See: Issue #121 — Rewrite container-runtime benchmarks to measure real fork latency
// See: benches/fork_latency.rs
//
// The [[bench]] entry in Cargo.toml is retained to avoid breaking any tooling
// that references the bench name. This file produces no benchmarks.

use criterion::{criterion_group, criterion_main, Criterion};

fn placeholder(_c: &mut Criterion) {
    // No benchmarks — see benches/fork_latency.rs
}

criterion_group!(benches, placeholder);
criterion_main!(benches);
