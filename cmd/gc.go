// gc.go — cobra command for `fastenv gc`.
//
// gc runs a GC sweep over all fork snapshots, applying TTL and LRU eviction
// policies, and prints a summary of forks evicted and bytes reclaimed. It also
// serves as the explicit trigger for the same lazy GC logic that runs on every
// `fastenv fork` and `fastenv discard` call.
//
// # Usage
//
//	fastenv gc [--gc-ttl <duration>] [--gc-max-disk <bytes>]
//
// # Design
//
// GC logic lives in [internal/gcer.RunGC]. This file handles CLI argument
// parsing, flag wiring, and structured JSON output. The --gc-ttl and
// --gc-max-disk flags are registered as persistent flags on the root command
// so they apply to fork and discard (lazy GC) as well.
//
// On success a structured JSON log line is written per evicted fork:
//
//	{"fork_id":"...","reason":"ttl|lru|explicit","bytes_reclaimed":N}
//
// Followed by a summary line on stdout:
//
//	{"forks_evicted":N,"bytes_reclaimed":N}
//
// # Canonical docs
//
//   - docs/architecture.md §5 OD-3 (fork GC scheduling)
//   - docs/implementation-plan.md Phase 6 (GC)
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/superfield-ai/fastenv/internal/gcer"
)

// newGCCmd returns the cobra command for the gc subcommand.
//
// gc triggers lazy TTL/LRU fork eviction plus an explicit manual collection pass.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 6 (GC)
//   - docs/architecture.md §5 OD-3 (fork GC scheduling)
func newGCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gc",
		Short: "Collect and remove expired or unused fork snapshots",
		Long: `Run a GC pass over all fastenv fork snapshots in the configured containerd
namespace. Forks past their TTL or beyond the LRU eviction threshold are
removed via containerd's snapshot Remove API.

GC is also triggered automatically on every fork and discard invocation
(lazy GC). This subcommand allows explicit manual collection.

Per-eviction structured JSON log lines are written to stdout:

  {"fork_id":"...","reason":"ttl|lru","bytes_reclaimed":N}

A final summary line is printed after all evictions:

  {"forks_evicted":N,"bytes_reclaimed":N}

Use --gc-ttl (or set it globally) to control the TTL window.
Use --gc-max-disk (or set it globally) to control the LRU disk budget.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := gcer.RunGC(cmd.Context(), gcer.Options{
				SocketPath: containerdSocket,
				Namespace:  containerdNamespace,
				TTL:        gcTTL,
				MaxDisk:    gcMaxDisk,
				Out:        cmd.OutOrStdout(),
			})
			if err != nil {
				return fmt.Errorf("gc: %w", err)
			}

			// Emit summary JSON line.
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetEscapeHTML(false)
			if err := enc.Encode(result); err != nil {
				return fmt.Errorf("gc: encode result: %w", err)
			}
			return nil
		},
	}
	return cmd
}
