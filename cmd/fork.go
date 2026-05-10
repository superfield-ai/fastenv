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
//	fastenv fork --base <base-image> --name <fork-id> [--quota <size>]
//
// # Design
//
// The --base flag names an image built by `fastenv build-base`. The --name
// flag assigns the fork's writable snapshot key (and user-visible ID). The
// optional --quota flag sets a per-fork disk quota limit (e.g. 10MiB). If
// a fork with the same name already exists, or if the base image does not
// exist, the command exits with a descriptive error.
//
// On success, a structured JSON log line is written to stdout:
//
//	{"fork_id":"...","base_image":"...","snapshot_key":"...","creation_latency":"...","quota_bytes":10485760,"quota_mode":"soft"}
//
// quota_mode is "soft" on hosts without project quotas and "hard" on hosts
// with ext4/xfs prjquota enabled on the containerd snapshot root.
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 2 (fork), Phase 5 (quotas)
//   - docs/architecture.md §2 (containerd as snapshot manager), §5 OD-4 (quotas)
//   - docs/quota-prerequisites.md (host filesystem prerequisites)
//   - docs/scout/phase1-findings.md §1 Phase B (snapshot Prepare for fork)
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/superfield-ai/fastenv/internal/forker"
	"github.com/superfield-ai/fastenv/internal/quota"
)

// newForkCmd returns the cobra command for the fork subcommand.
func newForkCmd() *cobra.Command {
	var (
		baseImage string
		forkName  string
		quotaStr  string
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

The optional --quota flag sets a per-fork disk limit (e.g. 10MiB, 1GiB).
On hosts without project quota support the quota is informational only (soft
mode): fastenv du will warn when usage exceeds the limit but writes are never
rejected. On hosts with ext4/xfs prjquota enabled, the limit is enforced at
the kernel level (hard mode): writes exceeding the quota fail with EDQUOT.
See docs/quota-prerequisites.md for host setup instructions.

On success a structured JSON log line is written to stdout:

  {"fork_id":"...","base_image":"...","snapshot_key":"...","creation_latency":"..."}

Exit with a descriptive error if:
  - the named base image does not exist (run 'fastenv build-base' first)
  - a fork with the same name already exists
  - the --quota value cannot be parsed`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if baseImage == "" {
				return fmt.Errorf("--base is required: supply the base image name (e.g. my-workspace)")
			}
			if forkName == "" {
				return fmt.Errorf("--name is required: supply the fork ID (e.g. agent-1)")
			}

			// Parse --quota if provided.
			var quotaBytes int64
			if quotaStr != "" {
				var err error
				quotaBytes, err = quota.Parse(quotaStr)
				if err != nil {
					return fmt.Errorf("--quota: %w", err)
				}
			}

			result, err := forker.Fork(cmd.Context(), baseImage, forkName, forker.Options{
				SocketPath: containerdSocket,
				Namespace:  containerdNamespace,
				QuotaBytes: quotaBytes,
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
	cmd.Flags().StringVar(&quotaStr, "quota", "",
		"per-fork disk quota limit (e.g. 10MiB, 1GiB); soft on most hosts, hard on ext4/xfs with prjquota")

	return cmd
}
