// du.go — cobra command for `fastenv du`.
//
// du reports the writable layer disk usage for a fork, broken down into
// workspace writes and cache writes (npm, pip, cargo). Base image bytes are
// excluded — only bytes written by this fork since creation are counted.
//
// When the fork was created with a --quota limit, du also checks whether the
// current usage exceeds the quota and logs a structured warning to stderr.
//
// # Usage
//
//	fastenv du <fork-id>
//
// # Output
//
// On success a structured JSON log line is written to stdout:
//
//	{
//	  "fork_id": "agent-1",
//	  "total_bytes": 12345,
//	  "workspace_bytes": 10000,
//	  "cache_bytes": 2345,
//	  "cache_breakdown": {"pip": 1200, "npm": 1145}
//	}
//
// # Quota warning
//
// When the fork has a fastenv.fork.quota snapshot label and usage exceeds the
// limit, an additional structured warning is written to stderr:
//
//	{"level":"warn","fork_id":"...","usage_bytes":...,"quota_bytes":...,"overage_bytes":...}
//
// The warning is informational on hosts without project quotas (soft mode).
// On hosts with ext4/xfs prjquota enabled, the kernel rejects over-quota
// writes before they reach du.
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 4 (du), Phase 5 (shared caches), Phase 5 (quotas)
//   - docs/architecture.md §5 OD-4 (quota enforcement)
//   - docs/quota-prerequisites.md (host filesystem prerequisites)
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/spf13/cobra"

	"github.com/superfield-ai/fastenv/internal/duer"
	"github.com/superfield-ai/fastenv/internal/quota"
)

// duWarning is emitted to stderr when usage exceeds the fork quota.
type duWarning struct {
	Level        string `json:"level"`
	ForkID       string `json:"fork_id"`
	UsageBytes   int64  `json:"usage_bytes"`
	QuotaBytes   int64  `json:"quota_bytes"`
	OverageBytes int64  `json:"overage_bytes"`
}

// newDuCmd returns the cobra command for the du subcommand.
//
// du reports the writable layer size delta for a fork, excluding base image
// bytes. When the fork has a quota label, usage is compared against the limit
// and a warning is emitted to stderr if the limit is exceeded.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 4 (du), Phase 5 (shared caches), Phase 5 (quotas)
//   - docs/architecture.md §5 OD-4 (quota enforcement)
func newDuCmd() *cobra.Command {
	var (
		rawBytes bool
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "du <fork-id>",
		Short: "Report writable layer disk usage for a fork",
		Long: `Report the disk usage of a fork's writable overlayfs upper layer.
Base image bytes are excluded — only the delta written by this fork is counted.

Cache writes (to /cache/npm, /cache/pip, /cache/cargo) are reported separately
from workspace writes, so operators can see how much cache the fork has produced
versus workspace output.

When the fork was created with --quota, du checks whether usage exceeds the
quota limit and emits a structured warning line to stderr. No enforcement is
applied by du itself; on hosts with ext4/xfs prjquota enabled the kernel
rejects over-quota writes before they reach du.

On hosts without project quota support this is a measurement-only report.
Hard quota enforcement requires ext4 or xfs with prjquota enabled.
See docs/quota-prerequisites.md for setup instructions.

Exit with a descriptive error if:
  - the fork does not exist or has been discarded
  - the containerd daemon cannot be reached`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			forkID := args[0]

			result, err := duer.Du(cmd.Context(), forkID, duer.Options{
				SocketPath: containerdSocket,
				Namespace:  containerdNamespace,
			})
			if err != nil {
				return fmt.Errorf("du: %w", err)
			}

			switch {
			case jsonOut:
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				if err := enc.Encode(result); err != nil {
					return fmt.Errorf("encode result: %w", err)
				}
			case rawBytes:
				fmt.Fprintf(cmd.OutOrStdout(), "%d\n", result.TotalBytes)
			default:
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				if err := enc.Encode(result); err != nil {
					return fmt.Errorf("encode result: %w", err)
				}
			}

			// Check quota: read fastenv.fork.quota label from snapshot labels.
			// Best-effort: skip warning if the label cannot be read (e.g. no
			// quota was set, or containerd is temporarily unavailable).
			quotaBytes, err := snapshotQuotaLabel(containerdSocket, containerdNamespace, forkID)
			if err == nil && quotaBytes > 0 && result.TotalBytes > quotaBytes {
				warn := duWarning{
					Level:        "warn",
					ForkID:       forkID,
					UsageBytes:   result.TotalBytes,
					QuotaBytes:   quotaBytes,
					OverageBytes: result.TotalBytes - quotaBytes,
				}
				warnEnc := json.NewEncoder(cmd.ErrOrStderr())
				warnEnc.SetEscapeHTML(false)
				_ = warnEnc.Encode(warn)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&rawBytes, "bytes", false, "print raw byte count instead of human-readable size")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print machine-readable JSON output")

	return cmd
}

// snapshotQuotaLabel reads the fastenv.fork.quota label directly from the
// containerd snapshot service for forkID. Returns 0 when the label is absent.
//
// A separate containerd connection is used because the Snapshotter interface
// does not expose snapshot label reads; that is a containerd-internal API.
func snapshotQuotaLabel(socketPath, namespace, forkID string) (int64, error) {
	const dialTimeout = 5 * time.Second
	if socketPath == "" {
		socketPath = "/run/containerd/containerd.sock"
	}
	if namespace == "" {
		namespace = "fastenv"
	}

	client, err := containerd.New(socketPath,
		containerd.WithDefaultNamespace(namespace),
		containerd.WithTimeout(dialTimeout),
	)
	if err != nil {
		return 0, fmt.Errorf("dial containerd: %w", err)
	}
	defer client.Close()

	ctx := namespaces.WithNamespace(context.Background(), namespace)
	info, err := client.SnapshotService("overlayfs").Stat(ctx, forkID)
	if err != nil {
		return 0, fmt.Errorf("stat snapshot %q: %w", forkID, err)
	}

	labelStr, ok := info.Labels[quota.LabelKey]
	if !ok || labelStr == "" {
		return 0, nil
	}

	v, err := strconv.ParseInt(labelStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse quota label %q: %w", labelStr, err)
	}
	return v, nil
}
