// export_patch.go — cobra command for `fastenv export-patch`.
//
// export-patch walks the fork's writable layer delta and produces a unified
// diff patch file that can be applied to the base source tree via `git apply`
// or `patch -p1`.
//
// # Output
//
// By default the patch is written to stdout. Use --output to write to a file.
//
// # Binary files
//
// Binary files are skipped by default with a warning to stderr. Use
// --include-binary to include them as git binary patch hunks.
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 4 (export-patch)
//   - docs/architecture.md §2 (containerd as snapshot manager)
package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/superfield-ai/fastenv/internal/patcher"
)

// newExportPatchCmd returns the cobra command for the export-patch subcommand.
//
// export-patch serializes writable layer changes as an applicable patch file.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 4 (export-patch)
func newExportPatchCmd() *cobra.Command {
	var (
		outputFile    string
		includeBinary bool
	)

	cmd := &cobra.Command{
		Use:   "export-patch <fork-id>",
		Short: "Export a fork's writable layer changes as a unified diff patch",
		Long: `Serialize the writable overlayfs upper layer of a fork as a unified
diff patch that can be applied to a pristine base checkout via:

  fastenv export-patch agent-1 | git apply

Or written to a file:

  fastenv export-patch agent-1 --output changes.patch

Binary files are skipped by default (with a warning to stderr). Use
--include-binary to include them as git binary patch hunks.

Deleted files are represented as deletion patches. The command does not
require the fork to be idle — it is safe to call while a command is
executing inside the fork.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			forkID := args[0]

			// Determine the output writer.
			var out io.Writer
			if outputFile != "" {
				f, err := os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("export-patch: create output file %q: %w", outputFile, err)
				}
				defer f.Close()
				out = f
			} else {
				out = cmd.OutOrStdout()
			}

			return patcher.ExportPatch(cmd.Context(), forkID, out, patcher.Options{
				SocketPath:    containerdSocket,
				Namespace:     containerdNamespace,
				IncludeBinary: includeBinary,
				Stderr:        cmd.ErrOrStderr(),
			})
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "write patch to file instead of stdout")
	cmd.Flags().BoolVar(&includeBinary, "include-binary", false, "include binary files as git binary patch hunks")

	return cmd
}
