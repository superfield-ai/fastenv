// unmount.go — cobra command for `fastenv unmount`.
//
// unmount removes the overlayfs mount created by `fastenv mount-path` and
// deletes the mount directory. Must be called before discarding a fork that
// was previously mounted with mount-path.
//
// # Usage
//
//	fastenv unmount <fork-id>
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 4 (mount-path subcommand)
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/superfield-ai/fastenv/internal/mounter"
)

func newUnmountCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unmount <fork-id>",
		Short: "Unmount a fork's filesystem previously mounted by mount-path",
		Long: `Remove the overlayfs mount at /run/fastenv/mounts/<fork-id> created by
'fastenv mount-path'. Must be called before discarding a mounted fork.

Requires CAP_SYS_ADMIN (run as root or with appropriate privileges).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			forkKey := args[0]
			if err := mounter.Unmount(forkKey); err != nil {
				return fmt.Errorf("unmount: %w", err)
			}
			log.Info("unmounted", "fork_key", forkKey)
			return nil
		},
	}
}
