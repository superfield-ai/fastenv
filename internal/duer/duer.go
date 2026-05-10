// Package duer implements the du (disk usage) lifecycle: reporting writable
// layer bytes for a fork, broken down into workspace writes and cache writes.
//
// # Design
//
//  1. Dial containerd and enter the configured namespace.
//  2. Stat the fork snapshot to confirm it exists.
//  3. Query the overlayfs snapshotter's Usage() for total writable bytes.
//  4. Find the fork's overlayfs upper directory by inspecting the mount options
//     for the active snapshot.
//  5. Walk the upper directory and classify each file by path:
//     - Files under cache/<name>/ are counted as cache writes.
//     - All other files are counted as workspace writes.
//  6. Return structured metadata with total, workspace, and cache byte counts.
//
// # Cache write separation
//
// This separation satisfies acceptance criterion #3 for issue #12:
//
//	"fastenv du agent-1 reports cache writes separately from workspace writes."
//
// The classification uses cachemanager.IsCachePath which recognises the paths
// /cache/npm/, /cache/pip/, and /cache/cargo/ as managed cache directories.
//
// # Canonical docs
//
//   - docs/prd.md §2 (success metrics: writable layer growth)
//   - docs/architecture.md §5 OD-4 (quota / du)
//   - docs/implementation-plan.md Phase 4 (inspection: du), Phase 5 (shared caches)
package duer

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	cerrdefs "github.com/containerd/errdefs"

	"github.com/superfield-ai/fastenv/internal/cachemanager"
)

const (
	dialTimeout     = 10 * time.Second
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

// DuResult holds disk usage metrics for a fork, emitted as a structured JSON
// log line upon successful completion.
type DuResult struct {
	// ForkID is the caller-assigned name for this fork.
	ForkID string `json:"fork_id"`
	// TotalBytes is the total number of bytes written into the fork's writable
	// upper layer (workspace + cache writes combined).
	TotalBytes int64 `json:"total_bytes"`
	// WorkspaceBytes is the number of bytes in the writable layer that fall
	// outside any managed cache directory (i.e. workspace writes).
	WorkspaceBytes int64 `json:"workspace_bytes"`
	// CacheBytes is the number of bytes written to managed cache directories
	// (/cache/npm, /cache/pip, /cache/cargo) inside the fork.
	CacheBytes int64 `json:"cache_bytes"`
	// CacheBreakdown maps each cache name (e.g. "pip") to the bytes written
	// to that cache directory by this fork.
	CacheBreakdown map[string]int64 `json:"cache_breakdown,omitempty"`
}

// Du reports the writable layer disk usage for forkID, broken down into
// workspace writes and cache writes.
//
// Returns an error if the fork does not exist or the containerd daemon cannot
// be reached. Returns a zeroed DuResult (all zero bytes) if the fork has made
// no writes.
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

	// Step 1: Confirm the fork exists.
	info, err := sn.Stat(ctx, forkID)
	if err != nil {
		if errors.Is(err, cerrdefs.ErrNotFound) {
			return nil, fmt.Errorf("du: fork %q not found — run 'fastenv fork' first", forkID)
		}
		return nil, fmt.Errorf("du: stat snapshot %q: %w", forkID, err)
	}

	// Only active (mutable) snapshots represent forks.
	if info.Kind != snapshots.KindActive {
		return nil, fmt.Errorf("du: %q is not an active fork snapshot (kind=%s)", forkID, info.Kind)
	}

	// Step 2: Query containerd's Usage() for the total writable bytes.
	// Usage() counts bytes in the snapshot's upper dir via the containerd
	// snapshotter's internal accounting.
	usage, err := sn.Usage(ctx, forkID)
	if err != nil {
		return nil, fmt.Errorf("du: usage for %q: %w", forkID, err)
	}

	// Step 3: Find the overlayfs upper directory for the fork.
	// We retrieve the mount descriptors from the snapshotter and parse the
	// upperdir option from the overlayfs mount.
	mounts, err := sn.Mounts(ctx, forkID)
	if err != nil {
		return nil, fmt.Errorf("du: mounts for %q: %w", forkID, err)
	}

	upperDir, err := findUpperDir(mounts)
	if err != nil {
		// Fall back to reporting total bytes only (no breakdown).
		return &DuResult{
			ForkID:         forkID,
			TotalBytes:     usage.Size,
			WorkspaceBytes: usage.Size,
			CacheBytes:     0,
		}, nil
	}

	// Step 4: Walk the upper directory and classify bytes by path.
	breakdown, totalActual, err := walkAndClassify(upperDir)
	if err != nil {
		// Walk failed; fall back to containerd's accounting.
		return &DuResult{
			ForkID:         forkID,
			TotalBytes:     usage.Size,
			WorkspaceBytes: usage.Size,
			CacheBytes:     0,
		}, nil
	}

	// Prefer the walk-based total over containerd's Usage() count so that the
	// breakdown sums to total exactly. containerd's Usage() may account for
	// directory metadata bytes differently.
	var cacheTotal int64
	cacheBreakdown := make(map[string]int64)
	for name, sz := range breakdown {
		cacheTotal += sz
		cacheBreakdown[name] = sz
	}

	return &DuResult{
		ForkID:         forkID,
		TotalBytes:     totalActual,
		WorkspaceBytes: totalActual - cacheTotal,
		CacheBytes:     cacheTotal,
		CacheBreakdown: cacheBreakdown,
	}, nil
}

// walkAndClassify walks the overlayfs upper directory, classifies each file
// as a cache write or a workspace write, and returns per-cache-name byte
// counts plus the total byte count.
func walkAndClassify(upperDir string) (cacheBytes map[string]int64, total int64, err error) {
	cacheBytes = make(map[string]int64)

	walkErr := filepath.WalkDir(upperDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable entries rather than aborting the walk.
			return nil
		}
		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		size := info.Size()
		total += size

		// Compute the path relative to the upper dir to classify it.
		rel, err := filepath.Rel(upperDir, path)
		if err != nil {
			return nil
		}

		if cachemanager.IsCachePath(rel) {
			// Attribute this file to the appropriate cache name.
			cacheName := extractCacheName(rel)
			cacheBytes[cacheName] += size
		}
		return nil
	})

	return cacheBytes, total, walkErr
}

// extractCacheName returns the cache subdirectory name from a relative path
// like "cache/pip/requests-2.31.0.tar.gz" → "pip".
// Returns an empty string if the path does not match the cache/ pattern.
func extractCacheName(rel string) string {
	// Normalise separators and strip a leading slash if present.
	rel = filepath.ToSlash(filepath.Clean(rel))
	rel = strings.TrimPrefix(rel, "/")
	parts := strings.SplitN(rel, "/", 3)
	if len(parts) >= 2 && parts[0] == "cache" {
		return parts[1]
	}
	return ""
}

// findUpperDir extracts the overlayfs upperdir path from a containerd mount
// option list. The overlayfs mount uses an option of the form:
//
//	"upperdir=/path/to/upper"
func findUpperDir(mounts []mount.Mount) (string, error) {
	for _, m := range mounts {
		if m.Type != "overlay" {
			continue
		}
		for _, opt := range m.Options {
			if strings.HasPrefix(opt, "upperdir=") {
				return strings.TrimPrefix(opt, "upperdir="), nil
			}
		}
	}
	// If no overlayfs upperdir is found, try the first bind mount target.
	for _, m := range mounts {
		if m.Type == "bind" && m.Source != "" {
			if _, err := os.Stat(m.Source); err == nil {
				return m.Source, nil
			}
		}
	}
	return "", fmt.Errorf("no overlayfs upperdir found in fork mount options")
}
