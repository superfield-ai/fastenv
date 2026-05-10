package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
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
	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Benchmark fork creation, exec start, and disk usage",
		Long: `Run a configurable benchmark suite measuring:

  - fork creation latency (p50/p95/p99) — target: p95 ≤ 100ms
  - exec start latency (p50/p95/p99)
  - writable layer size growth per fork
  - disk usage per fork (excluding base image bytes)
  - maximum concurrent forks under a memory/disk budget

Results are emitted as JSON to stdout for machine consumption.

See docs/scout/phase1-findings.md §5 for background on the latency budget
and the rationale for including snapshotter.Prepare microbenchmarks.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "bench: not yet implemented (Phase 6)")
			return nil
		},
	}
	return cmd
}
