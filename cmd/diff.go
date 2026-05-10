// diff.go — cobra command for `fastenv diff`.
//
// diff enumerates files changed in a fork's overlayfs writable layer relative
// to its base snapshot. It reads the overlay mount descriptors from containerd,
// locates the upperdir, and walks it to produce a list of changed paths.
//
// # Output formats
//
// Default (text): one line per changed file, prefixed with the status letter
// and a tab:
//
//	A	/workspace/newfile.txt
//	D	/etc/removed.cfg
//
// JSON (--json): a JSON array of objects with "path", "status", and "size":
//
//	[{"path":"/workspace/newfile.txt","status":"A","size":13}]
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 4 (diff)
//   - docs/architecture.md §2 (containerd as snapshot manager)
//   - docs/scout/phase1-findings.md §1 Phase B (overlayfs mount options, upperdir)
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/superfield-ai/fastenv/internal/differ"
)

// newDiffCmd returns the cobra command for the diff subcommand.
//
// diff enumerates files changed in a fork's writable layer relative to its
// base snapshot.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 4 (diff)
func newDiffCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "diff <fork-id>",
		Short: "List files changed in a fork's writable layer",
		Long: `Enumerate all files added, modified, or deleted in a fork's writable
overlayfs upper layer relative to the base snapshot.

Output format (default): one line per file, prefixed with A (added) or D (deleted).

  A	/workspace/newfile.txt
  D	/etc/removed.cfg

Output format (--json): JSON array of {path, status, size} objects.

The diff operates on the snapshot metadata without requiring the fork to be
idle: it is safe to call while a command is executing inside the fork.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			forkID := args[0]

			entries, err := differ.Diff(cmd.Context(), forkID, differ.Options{
				SocketPath: containerdSocket,
				Namespace:  containerdNamespace,
			})
			if err != nil {
				return fmt.Errorf("diff: %w", err)
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				// Emit a JSON array. Use an empty slice literal so the output is
				// "[]" rather than "null" when there are no changes.
				out := entries
				if out == nil {
					out = []differ.DiffEntry{}
				}
				if err := enc.Encode(out); err != nil {
					return fmt.Errorf("diff: encode JSON: %w", err)
				}
				return nil
			}

			// Text output: one line per entry, "<STATUS>\t<PATH>".
			for _, e := range entries {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", e.Status, e.Path)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit JSON array of {path, status, size} objects")

	return cmd
}
