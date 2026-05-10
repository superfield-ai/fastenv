// build_base.go — cobra command for `fastenv build-base`.
//
// build-base ingests a local source directory into containerd's content and
// image stores as an OCI image.  The resulting image is immutable and
// content-addressed, making it suitable as the base for fork operations.
//
// # Usage
//
//	fastenv build-base <source-dir> --name <image-name>
//
// # Design
//
// All heavy lifting is delegated to [internal/builder.BuildBase], which
// implements the OCI layer creation, content-store ingestion, and image
// registration.  This file only handles CLI argument parsing, flag wiring,
// and structured JSON output.
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 2 (build-base)
//   - docs/architecture.md §2 (containerd as content store)
//   - docs/scout/phase1-findings.md §1 Phase A (layer ingest sequence)
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/superfield-ai/fastenv/internal/builder"
)

// newBuildBaseCmd returns the cobra command for the build-base subcommand.
func newBuildBaseCmd() *cobra.Command {
	var imageName string

	cmd := &cobra.Command{
		Use:   "build-base <source-dir>",
		Short: "Build an immutable base workspace image from a local directory",
		Long: `Ingest a local directory into containerd's content store as a content-addressed
OCI image.  The resulting image serves as the immutable base for fork operations.

The image is tagged with the name supplied via --name.  Re-running build-base
with the same name overwrites the existing tag; unreferenced blobs are eligible
for containerd's background garbage collection.

On success a structured JSON log line is written to stdout:

  {"image_name":"...","manifest_digest":"sha256:...","total_size_bytes":0,"build_duration":"..."}

Package cache directories (npm, pip, cargo) within the source directory are
included in the single layer, keeping all dependency artifacts close to the
source tree for fast fork creation.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sourceDir := args[0]

			if imageName == "" {
				return fmt.Errorf("--name is required: supply the image tag (e.g. myproject:latest)")
			}

			result, err := builder.BuildBase(cmd.Context(), sourceDir, imageName, builder.Options{
				SocketPath: containerdSocket,
				Namespace:  containerdNamespace,
			})
			if err != nil {
				return fmt.Errorf("build-base: %w", err)
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

	cmd.Flags().StringVar(&imageName, "name", "", "image name/tag (required, e.g. myproject:latest)")

	return cmd
}
