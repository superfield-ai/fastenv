# Container Runtime Benchmark Artifact

Canonical schema reference for `docs/benchmarks/container-runtime-comparison.json`,
the JSON artifact produced by `.github/workflows/bench-container-runtime.yml`
(via `cargo bench --bench fork_latency [--features youki]`).

Issue #124 reworked this schema. The previous single-sample fields
(`fork_time_ms`, `first_write_ms`, `last_fork_ms`, `last_fw_ms`) have been
removed because any single outlier defined the published number. The new
schema reports nearest-rank percentiles over the full vector of successful
samples for each (backend, metric) pair.

## Top-level shape

```jsonc
[
  {
    "backend": "crun",
    "backend_verified": true,
    "fork_time":   { "n": 20, "p50_ms": ..., "p95_ms": ..., "p99_ms": ..., "min_ms": ..., "max_ms": ..., "stddev_ms": ... },
    "first_write": { "n": 10, "p50_ms": ..., "p95_ms": ..., "p99_ms": ..., "min_ms": ..., "max_ms": ..., "stddev_ms": ... }
  },
  {
    "backend": "youki",
    "backend_verified": true,
    "fork_time":   { ... },
    "first_write": { ... }
  }
]
```

The top-level value is an array with one object per backend that ran in this
workflow invocation. Older entries from prior runs are not preserved across
runs because the benchmark functions overwrite their own `(backend, metric)`
keys in place.

## Fields

| Field              | Type    | Meaning |
|--------------------|---------|---------|
| `backend`          | string  | `"crun"` or `"youki"`. |
| `backend_verified` | bool    | True if `/proc/*/cmdline` scanning confirmed the backend identity after the last sample (crun must appear for the crun backend; must NOT appear for the youki backend). |
| `fork_time`        | object  | Percentile summary for the fork_time metric (wall time from `backend.create()` to `backend.start()` return on a `/bin/true` workload). |
| `first_write`      | object  | Percentile summary for the first_write metric (wall time from `backend.start()` until a sentinel file written by the container appears on the host). |

### Percentile summary object

| Field       | Type    | Meaning |
|-------------|---------|---------|
| `n`         | integer | Number of successful samples that contributed to the percentiles. |
| `p50_ms`    | integer | 50th percentile (median) latency in milliseconds (nearest-rank). |
| `p95_ms`    | integer | 95th percentile latency in milliseconds (nearest-rank). |
| `p99_ms`    | integer | 99th percentile latency in milliseconds (nearest-rank). |
| `min_ms`    | integer | Minimum observed latency in milliseconds. |
| `max_ms`    | integer | Maximum observed latency in milliseconds. |
| `stddev_ms` | integer | Population standard deviation of the sample vector, in milliseconds (rounded to integer). |

A `(backend, metric)` pair only appears in the artifact when at least one
sample succeeded. If every iteration for that pair errored, the workflow fails
loud (issue #124's "fail-loud" requirement) rather than emit a fabricated
zero-valued entry.

## Comparing backends defensibly

A reader should be able to state "backend A is X% slower than backend B at
p95" from a single workflow run when:

1. Both backends ran in that workflow (`inputs.youki: true`).
2. `backend_verified` is true for both rows.
3. The difference between the two `p95_ms` values exceeds either backend's
   reported `stddev_ms`.

Both backends are guaranteed to measure equivalent work in the timed region:
`YoukiBackend::start` blocks on `waitpid(2)` for the container init process
and returns its real exit code, matching `CrunBackend::start`'s existing
`child.wait()` semantics (issue #124).

## Per-op microbenchmarks

The companion `benches/container_runtime.rs` only publishes `crun/start` and
`youki/start` results to Criterion (HTML report only — not to this JSON
artifact). The previous `create` / `delete` per-op benches were removed in
issue #124 because they timed structurally different work across backends
(`CrunBackend::delete` is a no-op, `YoukiBackend::delete` is a real libcontainer
call, and likewise for `create`).
