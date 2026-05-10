package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
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
removed via containerd's garbage collection API.

GC is also triggered automatically on every fork and discard invocation
(lazy GC). This subcommand allows explicit manual collection.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "gc: not yet implemented (Phase 6)")
			return nil
		},
	}
	return cmd
}
