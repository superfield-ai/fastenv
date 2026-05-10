// bench.go — cobra command for `fastenv bench`.
//
// bench runs the benchmark suite and emits results as JSON to stdout. It
// measures fork creation latency (p50/p95/p99), exec start latency, writable
// layer growth rate, disk usage per fork, and maximum concurrent forks.
//
// # Usage
//
//	fastenv bench --base <base-image> [--iterations N]
//
// # Output
//
// A single JSON document is written to stdout on completion. Structured log
// lines are written to stderr (controlled by the global --log-level flag).
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 6 (Observability)
//   - docs/architecture.md §5 OD-1 (observability tooling)
//   - docs/scout/phase1-findings.md §5 (fork latency baseline)
package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/superfield-ai/fastenv/internal/bencher"
	"github.com/superfield-ai/fastenv/internal/logger"
)

// newBenchCmd returns the cobra command for the bench subcommand.
//
// bench measures fork creation latency (p50/p95/p99), exec start latency,
// writable layer growth, disk usage per fork, and maximum concurrent forks.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 6 (Observability)
//   - docs/architecture.md §5 OD-1 (observability tooling)
//   - docs/scout/phase1-findings.md §5 (fork latency baseline)
func newBenchCmd() *cobra.Command {
	var (
		baseImage  string
		iterations int
	)

	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Benchmark fork creation, exec start, and disk usage",
		Long: `Run a configurable benchmark suite measuring:

  - fork creation latency (p50/p95/p99) — target: p95 ≤ 100ms, p50 ≤ 50ms
  - exec start latency (lower bound via fork creation measurement)
  - writable layer size growth per fork
  - disk usage per fork (excluding base image bytes)
  - maximum concurrent forks within the p95 latency budget

Results are emitted as a single JSON document to stdout for machine consumption.
Structured log lines describing progress are emitted to stderr.

The base image must already exist (built with 'fastenv build-base'). If
--base is omitted, the latency/disk benchmarks are skipped and the result
document notes that a base image is required.

See docs/scout/phase1-findings.md §5 for background on the latency budget
and the rationale for including snapshotter.Prepare microbenchmarks.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			start := time.Now()

			// log may be nil if PersistentPreRunE was skipped (e.g. in tests).
			// Fallback to a default info-level logger to stderr.
			l := log
			if l == nil {
				l = logger.New(logger.LevelInfo, cmd.ErrOrStderr())
			}

			l.Info("bench", "starting benchmark suite", logger.Fields{
				"base_image": baseImage,
				"iterations": iterations,
			})

			result, err := bencher.Bench(cmd.Context(), bencher.Options{
				SocketPath: containerdSocket,
				Namespace:  containerdNamespace,
				BaseImage:  baseImage,
				Iterations: iterations,
			})
			if err != nil {
				l.Error("bench", "benchmark failed", logger.Fields{"err": err.Error()})
				return fmt.Errorf("bench: %w", err)
			}

			l.Info("bench", "benchmark suite complete", logger.Fields{
				"duration":         time.Since(start).String(),
				"fork_p50_ms":      result.ForkCreation.Latency.P50Ms,
				"fork_p95_ms":      result.ForkCreation.Latency.P95Ms,
				"meets_budget_p50": result.ForkCreation.MeetsBudgetP50,
				"meets_budget_p95": result.ForkCreation.MeetsBudgetP95,
				"max_concurrent":   result.Concurrency.MaxForks,
				"disk_baseline_b":  result.DiskUsage.BaselineBytes,
			})

			// Emit the result JSON document to stdout.
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			if err := enc.Encode(result); err != nil {
				return fmt.Errorf("encode bench result: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&baseImage, "base", "",
		"base image name to fork from during benchmarks (required for latency/disk metrics)")
	cmd.Flags().IntVar(&iterations, "iterations", 10,
		"number of iterations for each latency benchmark")

	return cmd
}
