package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newForkCmd returns the cobra command for the fork subcommand.
//
// fork creates a CoW writable snapshot from a named base image targeting
// p50 ≤ 50ms and p95 ≤ 100ms fork creation latency.
//
// This command validates the --snapshotter flag before attempting any
// snapshot operation, so users receive a clear error (not a panic) when an
// unimplemented or unknown driver name is supplied.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 2 (fork)
//   - docs/scout/phase1-findings.md §1 Phase B (snapshot Prepare)
func newForkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fork <base-image> [fork-id]",
		Short: "Create a copy-on-write fork of a base workspace image",
		Long: `Allocate a new writable snapshot layer from an immutable base image using
containerd's snapshot Prepare API. The fork is ready for exec without
copying any base image bytes.

Fork creation targets p50 ≤ 50ms and p95 ≤ 100ms wall-clock latency.
If fork-id is omitted a unique ID is generated automatically.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate the --snapshotter driver before doing any work.
			// This satisfies the acceptance criterion from issue #3:
			//   "Swapping --snapshotter to an unimplemented value returns a
			//    clear error rather than a panic."
			sn, err := newSnapshotter()
			if err != nil {
				return err
			}
			defer sn.Close()

			fmt.Fprintln(cmd.ErrOrStderr(), "fork: not yet implemented (Phase 2)")
			return nil
		},
	}
	return cmd
}
