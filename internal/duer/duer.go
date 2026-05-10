// Package duer implements the du subcommand: reporting the writable layer disk
// usage for a fork, excluding base image bytes.
//
// # Design
//
//  1. Dial containerd and enter the configured namespace.
//  2. Call the snapshotter's Usage(forkKey) to retrieve bytes consumed by the
//     writable layer delta (upper dir only). Base image bytes are excluded.
//  3. If the fork does not exist, return a clear error.
//  4. Return structured metadata: fork ID, writable layer bytes, and a
//     human-readable size string.
//
// # Canonical docs
//
//   - docs/prd.md
//   - docs/architecture.md §5 OD-4 (quota enforcement)
//   - docs/implementation-plan.md Phase 4 (du)
package duer

import (
	"context"
	"errors"
	"fmt"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	cerrdefs "github.com/containerd/errdefs"
)

const (
	// dialTimeout is the maximum time to wait for a containerd gRPC connection.
	dialTimeout = 10 * time.Second

	// snapshotterName is the containerd snapshotter plugin used for du
	// operations. Must match the driver used at fork creation time.
	snapshotterName = "overlayfs"
)

// Options controls Du behaviour.
type Options struct {
	// SocketPath is the containerd gRPC Unix socket path.
	// Defaults to /run/containerd/containerd.sock if empty.
	SocketPath string
	// Namespace is the containerd namespace to operate in.
	// Defaults to "fastenv" if empty.
	Namespace string
}

// DuResult holds disk-usage metadata for a fork's writable layer.
// Base image bytes are not included.
type DuResult struct {
	// ForkID is the caller-assigned name for this fork.
	ForkID string `json:"fork_id"`
	// WritableLayerBytes is the number of bytes consumed by the writable
	// overlay layer (upper dir only). A freshly created fork with no writes
	// reports zero or near-zero.
	WritableLayerBytes int64 `json:"writable_layer_bytes"`
	// HumanSize is a human-readable representation of WritableLayerBytes
	// (e.g. "14 KiB", "1.0 MiB"). Always populated.
	HumanSize string `json:"human_size"`
}

// Du reports disk usage for the writable layer of forkID.
//
// Only bytes written by this fork (the overlayfs upper dir) are counted.
// The base image's committed snapshot chain is excluded.
//
// Returns an error if:
//   - forkID does not exist in the snapshot store (not found).
//   - the containerd daemon cannot be reached.
func Du(ctx context.Context, forkID string, opts Options) (*DuResult, error) {
	if opts.SocketPath == "" {
		opts.SocketPath = "/run/containerd/containerd.sock"
	}
	if opts.Namespace == "" {
		opts.Namespace = "fastenv"
	}

	client, err := containerd.New(opts.SocketPath,
		containerd.WithDefaultNamespace(opts.Namespace),
		containerd.WithTimeout(dialTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("du: dial containerd at %s: %w", opts.SocketPath, err)
	}
	defer client.Close()

	ctx = namespaces.WithNamespace(ctx, opts.Namespace)
	sn := client.SnapshotService(snapshotterName)

	// Usage reports bytes consumed by the writable layer (upper dir) only.
	// It excludes the parent snapshot chain (base image layers).
	usage, err := sn.Usage(ctx, forkID)
	if err != nil {
		if errors.Is(err, cerrdefs.ErrNotFound) {
			return nil, fmt.Errorf("du: fork %q does not exist or has been discarded", forkID)
		}
		return nil, fmt.Errorf("du: usage snapshot %q: %w", forkID, err)
	}

	return &DuResult{
		ForkID:             forkID,
		WritableLayerBytes: usage.Size,
		HumanSize:          humanBytes(usage.Size),
	}, nil
}

// humanBytes formats n bytes as a human-readable string using IEC binary
// prefixes (KiB, MiB, GiB, TiB). Values below 1 KiB are reported as "N B".
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	// exp=0 → KiB, exp=1 → MiB, exp=2 → GiB, exp=3 → TiB
	suffixes := []string{"KiB", "MiB", "GiB", "TiB"}
	suffix := suffixes[exp]
	value := float64(n) / float64(div)
	// Format with one decimal place only when not a whole number.
	if value == float64(int64(value)) {
		return fmt.Sprintf("%.0f %s", value, suffix)
	}
	return fmt.Sprintf("%.1f %s", value, suffix)
}
