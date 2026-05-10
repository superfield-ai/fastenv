package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newBuildBaseCmd returns the cobra command for the build-base subcommand.
//
// build-base ingests a local directory into a content-addressed OCI image in
// containerd's image store, including pre-populated package caches.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 2 (build-base)
func newBuildBaseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build-base <source-dir> <image-name>",
		Short: "Build an immutable base workspace image from a local directory",
		Long: `Ingest a local directory into containerd's content store as an OCI image.
The resulting image serves as the immutable base for fork operations.

Package cache directories (npm, pip, cargo) within the source directory are
stored as shared snapshot layers to minimise per-fork disk usage.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "build-base: not yet implemented (Phase 2)")
			return nil
		},
	}
	return cmd
}
