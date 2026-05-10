// fork.go — cobra command for `fastenv fork`.
//
// fork creates a CoW writable snapshot from a named base image targeting
// p50 ≤ 50ms and p95 ≤ 100ms fork creation latency. All heavy lifting is
// delegated to [internal/forker.Fork], which handles image lookup, layer
// unpack, and overlayfs Prepare. This file handles CLI argument parsing,
// flag wiring, and structured JSON output.
//
// # Usage
//
//	fastenv fork --base <base-image> --name <fork-id>
//
// # Design
//
// The --base flag names an image built by `fastenv build-base`. The --name
// flag assigns the fork's writable snapshot key (and user-visible ID). If
// a fork with the same name already exists, or if the base image does not
// exist, the command exits with a descriptive error.
//
// On success, a structured JSON log line is written to stdout:
//
//	{"fork_id":"...","base_image":"...","snapshot_key":"...","creation_latency":"..."}
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 2 (fork)
//   - docs/architecture.md §2 (containerd as snapshot manager)
//   - docs/scout/phase1-findings.md §1 Phase B (snapshot Prepare for fork)
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/superfield-ai/fastenv/internal/forker"
)

// newForkCmd returns the cobra command for the fork subcommand.
func newForkCmd() *cobra.Command {
	var (
		baseImage string
		forkName  string
	)

	cmd := &cobra.Command{
		Use:   "fork",
		Short: "Create a copy-on-write fork of a base workspace image",
		Long: `Allocate a new writable snapshot layer from an immutable base image using
containerd's overlayfs snapshot Prepare API. The fork is ready for exec
without copying any base image bytes.

Fork creation targets p50 ≤ 50ms and p95 ≤ 100ms wall-clock latency on a
warm base image. If the base image is not yet unpacked into the snapshotter,
the first fork will take longer while layers are applied.

On success a structured JSON log line is written to stdout:

  {"fork_id":"...","base_image":"...","snapshot_key":"...","creation_latency":"..."}

Exit with a descriptive error if:
  - the named base image does not exist (run 'fastenv build-base' first)
  - a fork with the same name already exists`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if baseImage == "" {
				return fmt.Errorf("--base is required: supply the base image name (e.g. my-workspace)")
			}
			if forkName == "" {
				return fmt.Errorf("--name is required: supply the fork ID (e.g. agent-1)")
			}

			result, err := forker.Fork(cmd.Context(), baseImage, forkName, forker.Options{
				SocketPath: containerdSocket,
				Namespace:  containerdNamespace,
			})
			if err != nil {
				return fmt.Errorf("fork: %w", err)
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

	cmd.Flags().StringVar(&baseImage, "base", "", "base image name to fork from (required)")
	cmd.Flags().StringVar(&forkName, "name", "", "fork ID / snapshot key (required)")

	return cmd
}
