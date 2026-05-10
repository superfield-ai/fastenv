package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
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
	cmd := &cobra.Command{
		Use:   "du <fork-id>",
		Short: "Report writable layer disk usage for a fork",
		Long: `Report the disk usage of a fork's writable overlayfs upper layer in bytes.
Base image bytes are excluded — only the delta written by this fork is counted.

On hosts without project quota support this is a measurement-only report.
Hard quota enforcement requires ext4 or xfs with prjquota enabled.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "du: not yet implemented (Phase 4)")
			return nil
		},
	}
	return cmd
}
