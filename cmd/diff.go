package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newDiffCmd returns the cobra command for the diff subcommand.
//
// diff enumerates files changed in a fork's writable layer relative to its
// base snapshot.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 4 (diff)
func newDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff <fork-id>",
		Short: "List files changed in a fork's writable layer",
		Long: `Enumerate all files added, modified, or deleted in a fork's writable
overlayfs upper layer relative to the base snapshot.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "diff: not yet implemented (Phase 4)")
			return nil
		},
	}
	return cmd
}
