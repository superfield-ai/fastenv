package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newDiscardCmd returns the cobra command for the discard subcommand.
//
// discard removes a fork's writable snapshot layer immediately.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 2 (discard)
//   - docs/scout/phase1-findings.md §1 Phase C (snapshot Remove)
func newDiscardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "discard <fork-id>",
		Short: "Remove a fork's writable snapshot layer immediately",
		Long: `Remove a named fork's writable overlayfs snapshot via containerd's
snapshotter.Remove API. The base image snapshot is unaffected.

Note: task lifecycle (exec) and snapshot lifecycle are separate. A fork can
only be discarded after its task has been deleted. See §2 of
docs/scout/phase1-findings.md for the task delete / snapshot remove order.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "discard: not yet implemented (Phase 2)")
			return nil
		},
	}
	return cmd
}
