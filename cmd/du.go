// du.go — cobra command for `fastenv du`.
//
// du reports the writable layer disk usage for a fork, broken down into
// workspace writes and cache writes (npm, pip, cargo). Base image bytes are
// excluded — only bytes written by this fork since creation are counted.
//
// # Usage
//
//	fastenv du <fork-id>
//
// # Output
//
// On success a structured JSON log line is written to stdout:
//
//	{
//	  "fork_id": "agent-1",
//	  "total_bytes": 12345,
//	  "workspace_bytes": 10000,
//	  "cache_bytes": 2345,
//	  "cache_breakdown": {"pip": 1200, "npm": 1145}
//	}
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 4 (du), Phase 5 (shared caches)
//   - docs/architecture.md §5 OD-4 (quota enforcement)
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/superfield-ai/fastenv/internal/duer"
)

// newDuCmd returns the cobra command for the du subcommand.
func newDuCmd() *cobra.Command {
	var (
		rawBytes bool
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "du <fork-id>",
		Short: "Report writable layer disk usage for a fork",
		Long: `Report the disk usage of a fork's writable overlayfs upper layer.
Base image bytes are excluded — only the delta written by this fork is counted.

Cache writes (to /cache/npm, /cache/pip, /cache/cargo) are reported separately
from workspace writes, so operators can see how much cache the fork has produced
versus workspace output.

On hosts without project quota support this is a measurement-only report.
Hard quota enforcement requires ext4 or xfs with prjquota enabled.

On success a structured JSON log line is written to stdout:

  {"fork_id":"...","total_bytes":0,"workspace_bytes":0,"cache_bytes":0}`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			forkID := args[0]

			result, err := duer.Du(cmd.Context(), forkID, duer.Options{
				SocketPath: containerdSocket,
				Namespace:  containerdNamespace,
			})
			if err != nil {
				return fmt.Errorf("du: %w", err)
			}

			switch {
			case jsonOut:
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				if err := enc.Encode(result); err != nil {
					return fmt.Errorf("encode result: %w", err)
				}
			case rawBytes:
				fmt.Fprintf(cmd.OutOrStdout(), "%d\n", result.TotalBytes)
			default:
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				if err := enc.Encode(result); err != nil {
					return fmt.Errorf("encode result: %w", err)
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&rawBytes, "bytes", false, "print raw byte count instead of human-readable size")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print machine-readable JSON output")

	return cmd
}
