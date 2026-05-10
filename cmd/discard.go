// discard.go — cobra command for `fastenv discard`.
//
// discard removes a fork's writable snapshot layer immediately via containerd's
// snapshotter.Remove API. The base image committed snapshot is unaffected.
//
// # Usage
//
//	fastenv discard <fork-id>
//
// # Design
//
// The <fork-id> argument names the fork's writable snapshot key (the same ID
// passed to `fastenv fork --name`). All heavy lifting is delegated to
// [internal/discarder.Discard], which handles snapshot lookup, usage
// measurement, removal, and a post-discard GC pass.
//
// The command is idempotent: discarding an already-discarded fork is a no-op
// (exits 0 with a zeroed bytes-freed report).
//
// On success a structured JSON log line is written to stdout:
//
//	{"fork_id":"...","writable_layer_bytes_freed":0,"duration":"..."}
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 2 (discard)
//   - docs/architecture.md §2 (containerd as snapshot manager)
//   - docs/scout/phase1-findings.md §1 Phase C (snapshot Remove)
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/superfield-ai/fastenv/internal/discarder"
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

Idempotent: discarding an already-discarded fork is a no-op (exits 0).

A GC pass is triggered after the discard to reclaim unreferenced storage.

On success a structured JSON log line is written to stdout:

  {"fork_id":"...","writable_layer_bytes_freed":0,"duration":"..."}

Exit with a descriptive error if:
  - the fork ID refers to a committed (base image) snapshot
  - the containerd daemon cannot be reached

Note: task lifecycle (exec) and snapshot lifecycle are separate. A fork can
only be discarded after its task has been deleted. See §2 of
docs/scout/phase1-findings.md for the task delete / snapshot remove order.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			forkID := args[0]

			result, err := discarder.Discard(cmd.Context(), forkID, discarder.Options{
				SocketPath: containerdSocket,
				Namespace:  containerdNamespace,
			})
			if err != nil {
				return fmt.Errorf("discard: %w", err)
			}

			// Emit structured JSON log line to stdout per acceptance criteria.
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetEscapeHTML(false)
			if err := enc.Encode(result); err != nil {
				return fmt.Errorf("encode result: %w", err)
			}
			return nil
		},
	}
	return cmd
}
