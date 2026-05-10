// mount_path.go — cobra command for `fastenv mount-path`.
//
// mount-path mounts a fork's overlayfs snapshot at a stable host path and
// prints that path to stdout. The primary consumer is Superfield's Firecracker
// CI runner: it passes the printed path to virtiofsd as the sharedDir so the
// fork's full merged workspace is visible inside the microVM via virtio-fs.
//
// # Usage
//
//	fastenv mount-path <fork-id>
//
// # Design
//
// The fork identified by <fork-id> must already exist (created by
// `fastenv fork`). containerd's Mounts API returns the overlayfs mount
// descriptors; this command applies them at /run/fastenv/mounts/<fork-id>
// using the standard mount(2) syscall and then prints that path to stdout.
//
// The mount persists until explicitly removed by `fastenv unmount <fork-id>`
// or until the host reboots. Callers are responsible for unmounting before
// discarding the fork.
//
// # Privileges
//
// mount(2) requires CAP_SYS_ADMIN. Run as root or with appropriate privileges.
//
// # Output
//
// On success, the host mount path is written to stdout (no trailing newline
// by default; use --json to get a structured JSON object):
//
//	/run/fastenv/mounts/agent-1
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 4 (mount-path subcommand)
//   - https://github.com/superfield-ai/superfield-cli-ts — Firecracker CI runner
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/superfield-ai/fastenv/internal/mounter"
)

// newMountPathCmd returns the cobra command for the mount-path subcommand.
func newMountPathCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "mount-path <fork-id>",
		Short: "Mount a fork's filesystem and print the host path",
		Long: `Mount the overlayfs snapshot for a fork at /run/fastenv/mounts/<fork-id>
and print the resulting host directory path to stdout.

The printed path can be passed directly to virtiofsd as the sharedDir to
share the fork's full merged workspace into a Firecracker microVM via
virtio-fs. The mount persists until 'fastenv unmount <fork-id>' is called
or the host reboots. Always unmount before discarding the fork.

Requires CAP_SYS_ADMIN (run as root or with appropriate privileges).

Example — share a workspace fork into a Firecracker VM:

  PATH=$(fastenv mount-path agent-1)
  virtiofsd --socket-path /tmp/vhostfs.sock --shared-dir "$PATH" &
  # ... start Firecracker VM with virtio-fs config pointing to vhostfs.sock ...
  fastenv unmount agent-1`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			forkKey := args[0]

			result, err := mounter.Mount(cmd.Context(), forkKey, mounter.Options{
				SocketPath: containerdSocket,
				Namespace:  containerdNamespace,
			})
			if err != nil {
				return fmt.Errorf("mount-path: %w", err)
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(result)
			}

			fmt.Fprint(cmd.OutOrStdout(), result.MountPath)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false,
		"emit structured JSON {mount_path, fork_key} instead of plain path")

	return cmd
}
