// du.go — cobra command for `fastenv du`.
//
// du reports the writable layer disk usage for a fork, excluding base image
// bytes. It calls Snapshotter.Usage(forkKey) which returns bytes consumed by
// the overlayfs upper dir (the writable delta) only.
//
// # Usage
//
//	fastenv du <fork-id> [--bytes] [--json]
//
// # Output modes
//
// Default: human-readable size string (e.g. "14 KiB").
// --bytes: raw byte count (e.g. "14336").
// --json:  machine-readable JSON object.
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 4 (du)
//   - docs/architecture.md §5 OD-4 (quota enforcement)
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/superfield-ai/fastenv/internal/duer"
)

// newDuCmd returns the cobra command for the du subcommand.
//
// du reports the writable layer size delta for a fork, excluding base image
// bytes.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 4 (du)
//   - docs/architecture.md §5 OD-4 (quota enforcement)
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

By default the size is printed in human-readable IEC format (e.g. "14 KiB").
Use --bytes for the raw byte count or --json for machine-readable output.

Exit with a descriptive error if:
  - the fork does not exist or has been discarded
  - the containerd daemon cannot be reached`,
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
				fmt.Fprintf(cmd.OutOrStdout(), "%d\n", result.WritableLayerBytes)
			default:
				fmt.Fprintf(cmd.OutOrStdout(), "%s\n", result.HumanSize)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&rawBytes, "bytes", false, "print raw byte count instead of human-readable size")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print machine-readable JSON output")

	return cmd
}
