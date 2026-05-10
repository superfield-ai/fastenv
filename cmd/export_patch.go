package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newExportPatchCmd returns the cobra command for the export-patch subcommand.
//
// export-patch serializes writable layer changes as an applicable patch file.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 4 (export-patch)
func newExportPatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export-patch <fork-id> [output-file]",
		Short: "Export a fork's writable layer changes as a patch file",
		Long: `Serialize the writable overlayfs upper layer of a fork as a tar-format
patch file that can be applied to a pristine base image to reproduce the
fork's filesystem state.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "export-patch: not yet implemented (Phase 4)")
			return nil
		},
	}
	return cmd
}
