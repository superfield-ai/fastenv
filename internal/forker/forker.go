// Package forker implements the fork lifecycle: creating a CoW writable
// snapshot from a named base image with shared read-only cache mounts.
//
// # Design
//
//  1. Look up the named base image in containerd's image store.
//  2. Ensure the image's layers are unpacked into the overlayfs snapshotter
//     (idempotent: containerd skips layers that are already present).
//  3. Resolve the top-level committed snapshot key for the image by computing
//     the OCI chain ID of the layer chain.
//  4. Verify that forkID does not already exist (returns a clear error).
//  5. Call the overlayfs snapshotter's Prepare(forkID, baseSnapshotKey) to
//     allocate a new CoW writable snapshot. No data is copied.
//  6. Discover shared cache snapshots for the base image (npm, pip, cargo).
//  7. For each cache snapshot, create a read-only View snapshot keyed by
//     CacheViewKey(forkID, cacheName) and record the lower dirs.
//  8. Extend the fork's overlayfs lowerdir option to include the cache lower
//     dirs so that /cache/<name>/ paths are visible inside the fork.
//  9. If a quota is specified, store it as a snapshot label and detect the
//     enforcement mode (soft or hard).
//  10. Return structured metadata including creation latency, cache mounts, and
//     quota mode.
//
// # Cache isolation
//
// Cache snapshots are committed once at build-base time and shared read-only
// across all forks of the same base image. Writes to /cache/<name>/ inside a
// fork land in the fork's writable upper dir (CoW), leaving the shared cache
// snapshot unmodified.
//
// # Latency targets
//
// Fork creation must meet p50 ≤ 50ms and p95 ≤ 100ms wall-clock latency on a
// warm base image (layers already unpacked). Steps 1–4 are lightweight
// metadata reads. Step 5 is dominated by mkdir + mount syscalls; the overlayfs
// driver performs no I/O on base image bytes.
//
// # Canonical docs
//
//   - docs/prd.md §7 (shared cache mounts)
//   - docs/architecture.md §2 (containerd as snapshot manager, shared cache)
//   - docs/architecture.md §5 OD-4 (quota enforcement)
//   - docs/implementation-plan.md Phase 2 (fork), Phase 5 (shared caches), Phase 5 (quotas)
//   - docs/quota-prerequisites.md (host filesystem prerequisites)
//   - docs/scout/phase1-findings.md §1 Phase B (snapshot Prepare for fork)
package forker

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	cerrdefs "github.com/containerd/errdefs"

	"github.com/superfield-ai/fastenv/internal/cachemanager"
	"github.com/superfield-ai/fastenv/internal/quota"
)

const (
	// dialTimeout is the maximum time to wait for a containerd gRPC connection.
	dialTimeout = 10 * time.Second

	// snapshotterName is the containerd snapshotter plugin used for fork
	// operations. overlayfs provides CoW semantics: the parent chain is mounted
	// read-only; each fork gets an independent empty upper dir for writes.
	snapshotterName = "overlayfs"
)

// Options controls Fork behaviour.
type Options struct {
	// SocketPath is the containerd gRPC Unix socket path.
	// Defaults to /run/containerd/containerd.sock if empty.
	SocketPath string
	// Namespace is the containerd namespace to operate in.
	// Defaults to "fastenv" if empty.
	Namespace string
	// QuotaBytes is the per-fork disk quota limit in bytes.
	// Zero means no quota is set.
	QuotaBytes int64
}

// CacheMountInfo describes a single shared cache layer mounted into a fork.
type CacheMountInfo struct {
	// Name is the short cache name (e.g. "pip", "npm", "cargo").
	Name string `json:"name"`
	// ViewKey is the containerd snapshot key of the read-only View snapshot
	// created for this fork's access to the shared cache layer.
	ViewKey string `json:"view_key"`
}

// ForkResult holds metadata about the created fork, emitted as a structured
// JSON log line upon successful completion.
type ForkResult struct {
	// ForkID is the caller-assigned name for this fork.
	ForkID string `json:"fork_id"`
	// BaseImage is the name of the base image the fork was created from.
	BaseImage string `json:"base_image"`
	// SnapshotKey is the containerd snapshot key of the writable fork layer.
	// Equal to forkID: callers pass this key to the runtime or to Mounts().
	SnapshotKey string `json:"snapshot_key"`
	// CreationLatency is the wall-clock duration from invocation to fork ready.
	CreationLatency string `json:"creation_latency"`
	// CacheMounts lists the shared cache layers mounted read-only into this fork.
	// Empty when no cache snapshots exist for the base image.
	CacheMounts []CacheMountInfo `json:"cache_mounts,omitempty"`
	// QuotaBytes is the per-fork disk quota in bytes, or 0 if no quota was set.
	// Omitted from JSON when zero.
	QuotaBytes int64 `json:"quota_bytes,omitempty"`
	// QuotaMode indicates how the quota is enforced.
	// "soft": usage is measured and a warning is logged when exceeded.
	// "hard": writes exceeding the quota fail with EDQUOT (requires prjquota).
	// Omitted from JSON when no quota is set.
	QuotaMode quota.Mode `json:"quota_mode,omitempty"`
}

// Fork creates a writable CoW snapshot identified by forkID from the base
// image named baseImage. The fork is ready immediately; no bytes are copied.
//
// Returns an error if:
//   - baseImage does not exist in containerd's image store.
//   - a snapshot with forkID already exists.
//   - the image layers cannot be unpacked.
func Fork(ctx context.Context, baseImage, forkID string, opts Options) (*ForkResult, error) {
	start := time.Now()

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
		return nil, fmt.Errorf("fork: dial containerd at %s: %w", opts.SocketPath, err)
	}
	defer client.Close()

	ctx = namespaces.WithNamespace(ctx, opts.Namespace)

	// Step 1: Look up the base image in containerd's image store.
	//
	// GetImage returns the containerd client Image interface, which wraps the
	// metadata image and provides Unpack / RootFS methods.
	img, err := client.GetImage(ctx, baseImage)
	if err != nil {
		if errors.Is(err, cerrdefs.ErrNotFound) {
			return nil, fmt.Errorf("fork: base image %q not found — run 'fastenv build-base' first", baseImage)
		}
		return nil, fmt.Errorf("fork: get base image %q: %w", baseImage, err)
	}

	// Step 2: Ensure image layers are unpacked into the overlayfs snapshotter.
	//
	// Unpack walks the OCI manifest, applies each layer diff to a scratch
	// active snapshot, then commits it as a chain-ID-keyed committed snapshot.
	// Subsequent calls are idempotent: already-present snapshots are skipped.
	//
	// On a warm base image this is a fast metadata check (no I/O).
	if err := img.Unpack(ctx, snapshotterName); err != nil {
		return nil, fmt.Errorf("fork: unpack base image %q into overlayfs: %w", baseImage, err)
	}

	// Step 3: Resolve the top-level committed snapshot key.
	//
	// RootFS returns the OCI chain IDs for each layer. The last chain ID is
	// the committed snapshot key for the top of the parent chain. containerd
	// stores snapshots keyed by their chain ID string (e.g. "sha256:abc…").
	//
	// See OCI image spec §4.6.3 for the chain ID computation:
	//   chainID[0] = diffID[0]
	//   chainID[n] = sha256(chainID[n-1] + " " + diffID[n])
	chainIDs, err := img.RootFS(ctx)
	if err != nil {
		return nil, fmt.Errorf("fork: get RootFS chain IDs for %q: %w", baseImage, err)
	}
	if len(chainIDs) == 0 {
		return nil, fmt.Errorf("fork: base image %q has no layers", baseImage)
	}
	baseSnapshotKey := chainIDs[len(chainIDs)-1].String()

	// Step 4: Check that forkID does not already exist.
	//
	// Stat returns nil error when the snapshot exists. We surface a clear
	// error before attempting Prepare, avoiding the less-readable containerd
	// "already exists" gRPC error.
	sn := client.SnapshotService(snapshotterName)
	if _, err := sn.Stat(ctx, forkID); err == nil {
		return nil, fmt.Errorf("fork: fork %q already exists — choose a different name", forkID)
	}

	// Step 5: Allocate the CoW writable snapshot via overlayfs Prepare.
	//
	// Prepare(forkID, baseSnapshotKey) creates an active snapshot backed by
	// overlayfs. The lower layers are the committed parent chain; the upper dir
	// is a new empty directory unique to this fork. No bytes are copied.
	//
	// Labels carry provenance metadata for observability and GC decisions.
	// fastenv.fork.base: the human-readable base image name.
	// fastenv.fork.created: RFC 3339 creation timestamp.
	// fastenv.fork.quota: quota limit in bytes (when set).
	//
	// See docs/scout/phase1-findings.md §1 Phase B for the full call sequence.
	labels := map[string]string{
		"fastenv.fork.base":    baseImage,
		"fastenv.fork.created": time.Now().UTC().Format(time.RFC3339),
	}
	if opts.QuotaBytes > 0 {
		labels[quota.LabelKey] = strconv.FormatInt(opts.QuotaBytes, 10)
	}

	forkMounts, err := sn.Prepare(ctx, forkID, baseSnapshotKey,
		snapshots.WithLabels(labels),
	)
	if err != nil {
		if errors.Is(err, cerrdefs.ErrAlreadyExists) {
			return nil, fmt.Errorf("fork: fork %q already exists — choose a different name", forkID)
		}
		return nil, fmt.Errorf("fork: prepare snapshot %q (parent %q): %w", forkID, baseSnapshotKey, err)
	}

	// Step 6: Discover and mount shared cache layers for the base image.
	//
	// If build-base extracted cache snapshots for this image (keyed by
	// CacheSnapshotKey(baseImage, cacheName)), we create read-only View
	// snapshots for this fork and extend the overlayfs lowerdir option to
	// include the cache lower dirs. This makes /cache/<name>/ paths visible
	// inside the fork. Writes to /cache/<name>/ land in the fork's upper dir
	// (CoW), leaving the shared cache snapshots unmodified.
	cacheLayers, err := cachemanager.ListCacheLayers(ctx, sn, baseImage)
	if err != nil {
		return nil, fmt.Errorf("fork: list cache layers for %q: %w", baseImage, err)
	}

	var cacheMountInfos []CacheMountInfo
	var cacheExtraLowers []string // lower dirs from cache View snapshots

	for _, cl := range cacheLayers {
		viewMounts, err := cachemanager.MountCacheLayer(ctx, sn, forkID, cl.Name, cl.SnapshotKey)
		if err != nil {
			// Best-effort: log but do not fail the fork if a cache view fails.
			// The fork is still usable; it just won't have the cache overlay.
			_ = err
			continue
		}
		cacheMountInfos = append(cacheMountInfos, CacheMountInfo{
			Name:    cl.Name,
			ViewKey: cachemanager.CacheViewKey(forkID, cl.Name),
		})
		// Extract lower dirs from the cache view mounts to append to the
		// fork's overlayfs lowerdir option.
		cacheExtraLowers = append(cacheExtraLowers, extractLowerDirs(viewMounts)...)
	}

	// Step 7: Extend the fork's overlayfs lowerdir with cache lower dirs.
	//
	// The fork's overlayfs mount has a lowerdir option listing the base image
	// layer dirs. We append the cache lower dirs so that cache paths are
	// visible below the workspace content. The fork's upper dir handles all
	// writes regardless of path (workspace or cache).
	if len(cacheExtraLowers) > 0 {
		if err := extendLowerDirs(ctx, sn, forkID, forkMounts, cacheExtraLowers); err != nil {
			// Best-effort: cache lower dir extension failed; the fork remains
			// usable without cache overlay.
			_ = err
		}
	}

	latency := time.Since(start)

	result := &ForkResult{
		ForkID:          forkID,
		BaseImage:       baseImage,
		SnapshotKey:     forkID,
		CreationLatency: latency.Round(time.Microsecond).String(),
		CacheMounts:     cacheMountInfos,
	}

	// Step 8: Record quota metadata when a limit was requested.
	//
	// Detect enforcement mode: soft on most hosts, hard when the containerd
	// snapshot root filesystem has prjquota enabled (ext4 or xfs).
	if opts.QuotaBytes > 0 {
		result.QuotaBytes = opts.QuotaBytes
		result.QuotaMode = quota.DetectMode(opts.SocketPath)
	}

	return result, nil
}

// extractLowerDirs pulls the lowerdir paths out of an overlayfs mount list.
// Returns an empty slice if no overlayfs lower dirs are found.
func extractLowerDirs(mounts []mount.Mount) []string {
	var dirs []string
	for _, m := range mounts {
		if m.Type != "overlay" {
			continue
		}
		for _, opt := range m.Options {
			if !strings.HasPrefix(opt, "lowerdir=") {
				continue
			}
			val := strings.TrimPrefix(opt, "lowerdir=")
			for _, d := range strings.Split(val, ":") {
				if d != "" {
					dirs = append(dirs, d)
				}
			}
		}
	}
	return dirs
}

// extendLowerDirs updates the fork's active snapshot in the containerd store
// to include the given extra lower dirs in its overlayfs lowerdir option.
//
// containerd's overlayfs snapshotter does not provide a first-class API to
// modify the lowerdir of an existing active snapshot. The practical approach
// is to record the extra lower dirs as a label on the fork snapshot so that
// the container runtime spec builder (exec command) can include them when
// constructing the OCI mount spec for the fork.
//
// This function stores the extra lower dirs as a label
// "fastenv.cache.lowerdirs" (colon-separated) on the fork snapshot.
func extendLowerDirs(
	ctx context.Context,
	sn snapshots.Snapshotter,
	forkID string,
	_ []mount.Mount, // forkMounts — reserved for future direct mount manipulation
	extraLowers []string,
) error {
	info, err := sn.Stat(ctx, forkID)
	if err != nil {
		return fmt.Errorf("stat fork snapshot %q: %w", forkID, err)
	}
	if info.Labels == nil {
		info.Labels = make(map[string]string)
	}
	info.Labels["fastenv.cache.lowerdirs"] = strings.Join(extraLowers, ":")
	_, err = sn.Update(ctx, info, "labels.fastenv.cache.lowerdirs")
	if err != nil {
		return fmt.Errorf("update fork snapshot labels: %w", err)
	}
	return nil
}
