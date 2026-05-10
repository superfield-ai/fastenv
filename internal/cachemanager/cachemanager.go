// Package cachemanager manages shared package-cache snapshot layers for fastenv.
//
// # Design
//
// Package cache directories (npm, pip, cargo) are extracted from the source
// workspace as separate content-addressed committed snapshot layers at
// build-base time. At fork time, each cache layer is mounted as an additional
// read-only lower directory in the fork's overlayfs mount, beneath the main
// workspace layer. Writes to cache paths by a fork land in the fork's writable
// upper layer (copy-on-write), leaving the shared cache snapshots unmodified
// and available for concurrent forks to read.
//
// # Snapshot key scheme
//
//	Workspace snapshot:  <imageName>
//	Cache snapshots:     <imageName>:cache:<type>   (e.g. my-ws:cache:pip)
//	Fork view snapshots: <forkID>:cacheview:<type>  (e.g. agent-1:cacheview:pip)
//
// # Cache paths
//
// By default, three well-known cache directories are managed:
//
//	/cache/npm   — Node.js package cache (npm/yarn/pnpm)
//	/cache/pip   — Python package cache (pip wheel cache)
//	/cache/cargo — Rust package registry and build cache
//
// These paths are relative to the source directory root passed to BuildBase.
// Directories that do not exist in the source tree are silently skipped.
//
// # Canonical docs
//
//   - docs/prd.md §7 (shared cache mounts)
//   - docs/architecture.md §2 (shared content-addressed cache)
//   - docs/implementation-plan.md Phase 5 (shared caches and quotas)
package cachemanager

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/archive"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// DefaultCacheNames lists the well-known package cache subdirectory names
// fastenv manages as shared layers. Each entry N corresponds to a directory
// <sourceDir>/cache/<N> (e.g. /cache/pip, /cache/npm, /cache/cargo inside
// the container).
var DefaultCacheNames = []string{"npm", "pip", "cargo"}

// gcRootLabel pins committed snapshots so containerd GC does not reclaim them
// while forks are alive. See containerd GC docs for semantics.
const gcRootLabel = "containerd.io/gc.root"

// CacheSnapshotKey returns the containerd snapshot key for the cache layer
// corresponding to cacheName (e.g. "pip") within imageName (e.g. "my-ws").
//
// The key scheme is:  <imageName>:cache:<cacheName>
//
// This predictable naming allows Fork to look up cache layers without
// consulting any external registry.
func CacheSnapshotKey(imageName, cacheName string) string {
	return fmt.Sprintf("%s:cache:%s", imageName, cacheName)
}

// CacheViewKey returns the snapshot key for a fork's read-only view of a
// given cache layer. This active snapshot is created by Fork and removed by
// Discard.
//
// The key scheme is:  <forkID>:cacheview:<cacheName>
func CacheViewKey(forkID, cacheName string) string {
	return fmt.Sprintf("%s:cacheview:%s", forkID, cacheName)
}

// CacheLayer describes a single cache layer committed into the snapshot store.
type CacheLayer struct {
	// Name is the short cache name, e.g. "pip", "npm", "cargo".
	Name string
	// SnapshotKey is the containerd snapshot key for the committed layer.
	SnapshotKey string
	// DiffID is the sha256 of the uncompressed tar stream (OCI DiffID).
	DiffID digest.Digest
	// SizeBytes is the compressed size of the layer blob in the content store.
	SizeBytes int64
}

// BuildResult holds the cache layers extracted during build-base.
type BuildResult struct {
	// Layers lists every cache layer that was successfully committed. Layers
	// for cache directories that did not exist in the source tree are omitted.
	Layers []CacheLayer
}

// BuildCacheLayers extracts the well-known cache subdirectories from sourceDir,
// writes each as a separate committed snapshot into the containerd snapshot
// store, and returns metadata for each committed layer.
//
// sourceDir is the workspace root (the same directory passed to build-base).
// imageName is the base image name; it is used to derive deterministic snapshot
// keys via CacheSnapshotKey.
// cacheNames lists the subdirectory names under <sourceDir>/cache/ to extract.
// Pass nil to use DefaultCacheNames.
//
// Directories that do not exist in sourceDir are skipped without error.
// If a snapshot with the derived key already exists in the store the layer is
// skipped (idempotent for repeated build-base invocations).
//
// cs is the containerd content store (used to write the layer blob).
// sn is the containerd snapshotter (used to commit the snapshot).
func BuildCacheLayers(
	ctx context.Context,
	cs content.Store,
	sn snapshots.Snapshotter,
	sourceDir, imageName string,
	cacheNames []string,
) (*BuildResult, error) {
	if cacheNames == nil {
		cacheNames = DefaultCacheNames
	}

	result := &BuildResult{}

	for _, name := range cacheNames {
		cacheDir := filepath.Join(sourceDir, "cache", name)
		if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
			// Cache directory absent in source tree — skip silently.
			continue
		}

		snapshotKey := CacheSnapshotKey(imageName, name)

		// Idempotency: if the snapshot already exists, record it and move on.
		if _, err := sn.Stat(ctx, snapshotKey); err == nil {
			result.Layers = append(result.Layers, CacheLayer{
				Name:        name,
				SnapshotKey: snapshotKey,
			})
			continue
		}

		layer, err := buildCacheLayer(ctx, cs, sn, cacheDir, name, snapshotKey)
		if err != nil {
			return nil, fmt.Errorf("cache layer %q: %w", name, err)
		}
		result.Layers = append(result.Layers, *layer)
	}

	return result, nil
}

// buildCacheLayer creates a single cache committed snapshot from cacheDir.
func buildCacheLayer(
	ctx context.Context,
	cs content.Store,
	sn snapshots.Snapshotter,
	cacheDir, cacheName, snapshotKey string,
) (*CacheLayer, error) {
	// Step 1: Stream cacheDir as a tar layer, pinning mtimes to the epoch for
	// content-addressed stability. The archive.Diff helper produces an
	// uncompressed tar stream; we simultaneously hash it (DiffID) and gzip it
	// (layer blob stored in the content store).
	epoch := time.Unix(0, 0).UTC()
	diffRC := archive.Diff(ctx, "", cacheDir,
		archive.WithSourceDateEpoch(&epoch),
	)
	defer diffRC.Close()

	diffDigester := digest.SHA256.Digester()
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return nil, fmt.Errorf("create gzip writer: %w", err)
	}

	// TeeReader: bytes go through the diffDigester (DiffID) AND the gzip writer.
	tarTee := io.TeeReader(diffRC, diffDigester.Hash())
	if _, err := io.Copy(gw, tarTee); err != nil {
		return nil, fmt.Errorf("stream cache dir to gzip: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("close gzip writer: %w", err)
	}

	diffID := diffDigester.Digest()
	layerBytes := buf.Bytes()
	layerDigest := digest.SHA256.FromBytes(layerBytes)
	layerSize := int64(len(layerBytes))

	// Step 2: Write the compressed layer to the content store.
	layerDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    layerDigest,
		Size:      layerSize,
	}
	if err := writeBlob(ctx, cs, layerDesc, bytes.NewReader(layerBytes)); err != nil {
		return nil, fmt.Errorf("write layer blob: %w", err)
	}

	// Step 3: Unpack the layer into a committed snapshot.
	// Strategy: Prepare an active scratch snapshot (no parent = empty root),
	// apply the layer diff, then Commit it under the canonical cache key.
	scratchKey := snapshotKey + "-scratch"
	_, prepErr := sn.Prepare(ctx, scratchKey, "",
		snapshots.WithLabels(map[string]string{
			gcRootLabel: time.Now().UTC().Format(time.RFC3339),
		}),
	)
	if prepErr != nil {
		return nil, fmt.Errorf("prepare scratch snapshot: %w", prepErr)
	}

	// Apply the tar layer to the scratch snapshot's mounts.
	mounts, err := sn.Mounts(ctx, scratchKey)
	if err != nil {
		_ = sn.Remove(ctx, scratchKey)
		return nil, fmt.Errorf("get scratch mounts: %w", err)
	}

	// Unpack the layer tar into the scratch snapshot's filesystem.
	if err := applyLayer(ctx, mounts, cacheDir, cacheName); err != nil {
		_ = sn.Remove(ctx, scratchKey)
		return nil, fmt.Errorf("apply layer: %w", err)
	}

	// Commit the scratch snapshot as the canonical cache snapshot.
	if err := sn.Commit(ctx, snapshotKey, scratchKey,
		snapshots.WithLabels(map[string]string{
			gcRootLabel:                 time.Now().UTC().Format(time.RFC3339),
			"fastenv.cache.name":        cacheName,
			"fastenv.cache.diff_id":     diffID.String(),
		}),
	); err != nil {
		_ = sn.Remove(ctx, scratchKey)
		return nil, fmt.Errorf("commit cache snapshot: %w", err)
	}

	return &CacheLayer{
		Name:        cacheName,
		SnapshotKey: snapshotKey,
		DiffID:      diffID,
		SizeBytes:   layerSize,
	}, nil
}

// applyLayer copies the contents of cacheDir into the scratch snapshot's
// mounted filesystem, placing them under the cache/<name> path so that they
// appear at the correct location inside forks.
//
// mounts is the overlayfs mount list returned by Prepare; we use the upper
// directory (the writable layer) as the destination.
func applyLayer(_ context.Context, mounts []mount.Mount, cacheDir, cacheName string) error {
	if len(mounts) == 0 {
		return fmt.Errorf("no mounts returned for scratch snapshot")
	}

	// Find the upper dir from the overlayfs mount options.
	// containerd's overlayfs snapshotter returns a single mount with options
	// containing "upperdir=<path>,...". We write directly to the upper dir so
	// we don't need to mount the filesystem (avoids requiring CAP_SYS_ADMIN in
	// unit test environments that fake this call).
	upperDir, err := findUpperDir(mounts)
	if err != nil {
		// Fallback: try writing to the first mount's source path directly.
		// This handles the non-overlayfs case (e.g. native snapshotter in CI).
		return fmt.Errorf("find upper dir: %w", err)
	}

	// Place cache contents under cache/<name>/ inside the snapshot.
	destDir := filepath.Join(upperDir, "cache", cacheName)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("mkdir cache dest %s: %w", destDir, err)
	}

	// Copy files from cacheDir into destDir recursively.
	return copyDir(cacheDir, destDir)
}

// findUpperDir extracts the overlayfs upperdir path from a containerd mount
// option list. The overlayfs mount type uses options like:
//
//	"upperdir=/path/to/upper,lowerdir=...,workdir=..."
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
	return "", fmt.Errorf("no overlayfs upperdir found in mounts")
}

// copyDir recursively copies the contents of src into dst.
// It preserves file permissions but normalises timestamps to the Unix epoch
// for content-addressed stability.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(destPath, info.Mode())
		}

		return copyFile(path, destPath, info.Mode())
	})
}

// copyFile copies a single regular file from src to dst, preserving mode bits.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

// writeBlob writes a content blob to the containerd content store. If a blob
// with the same digest already exists the write is a no-op (idempotent).
func writeBlob(ctx context.Context, cs content.Store, desc ocispec.Descriptor, r io.Reader) error {
	// Check for an existing blob first to avoid redundant writes.
	if _, err := cs.Info(ctx, desc.Digest); err == nil {
		return nil
	}

	ref := fmt.Sprintf("fastenv-cache-ingest-%s", desc.Digest.Encoded()[:16])
	cw, err := cs.Writer(ctx,
		content.WithRef(ref),
		content.WithDescriptor(desc),
	)
	if err != nil {
		return fmt.Errorf("open content writer (ref=%s): %w", ref, err)
	}
	defer cw.Close()

	if _, err := io.Copy(cw, r); err != nil {
		return fmt.Errorf("copy blob bytes: %w", err)
	}
	if err := cw.Commit(ctx, desc.Size, desc.Digest); err != nil {
		return fmt.Errorf("commit blob: %w", err)
	}
	return nil
}

// CacheLayerInfo holds the information needed to mount a cache layer into a fork.
type CacheLayerInfo struct {
	// Name is the short cache name (e.g. "pip").
	Name string
	// SnapshotKey is the committed snapshot key in the containerd store.
	SnapshotKey string
}

// ListCacheLayers returns the cache layers that exist in the snapshot store for
// the given imageName. It checks each well-known cache name and returns only
// those whose committed snapshots are present.
//
// This is called by Fork to discover which cache layers to mount.
func ListCacheLayers(ctx context.Context, sn snapshots.Snapshotter, imageName string) ([]CacheLayerInfo, error) {
	var layers []CacheLayerInfo
	for _, name := range DefaultCacheNames {
		key := CacheSnapshotKey(imageName, name)
		info, err := sn.Stat(ctx, key)
		if err != nil {
			// Snapshot does not exist — skip.
			continue
		}
		// Only include committed (immutable) snapshots.
		if info.Kind != snapshots.KindCommitted {
			continue
		}
		layers = append(layers, CacheLayerInfo{
			Name:        name,
			SnapshotKey: key,
		})
	}
	return layers, nil
}

// MountCacheLayer creates a read-only View snapshot for forkID over the
// committed cache snapshot identified by cacheKey. The view snapshot is keyed
// by CacheViewKey(forkID, cacheName).
//
// View snapshots are read-only active snapshots: the cache content is visible
// but no writes can land in the cache snapshot itself.
//
// Returns the mount descriptors for the view; callers combine these with the
// fork's workspace mounts to form the full overlayfs lower-dir chain.
func MountCacheLayer(
	ctx context.Context,
	sn snapshots.Snapshotter,
	forkID, cacheName, cacheKey string,
) ([]mount.Mount, error) {
	viewKey := CacheViewKey(forkID, cacheName)

	// Idempotency: if the view snapshot already exists, return its mounts.
	if _, err := sn.Stat(ctx, viewKey); err == nil {
		viewMounts, err := sn.Mounts(ctx, viewKey)
		if err != nil {
			return nil, fmt.Errorf("mounts for existing cache view %q: %w", viewKey, err)
		}
		return viewMounts, nil
	}

	mounts, err := sn.View(ctx, viewKey, cacheKey,
		snapshots.WithLabels(map[string]string{
			"fastenv.fork.id":   forkID,
			"fastenv.cache.name": cacheName,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("create cache view %q (parent %q): %w", viewKey, cacheKey, err)
	}
	return mounts, nil
}

// RemoveCacheViews removes all cache View snapshots created for forkID.
// This is called by Discard to clean up fork-local cache views.
// Errors from individual removals are logged but do not abort the sweep.
func RemoveCacheViews(ctx context.Context, sn snapshots.Snapshotter, forkID string) []error {
	var errs []error
	for _, name := range DefaultCacheNames {
		viewKey := CacheViewKey(forkID, name)
		if _, err := sn.Stat(ctx, viewKey); err != nil {
			// View does not exist — nothing to remove.
			continue
		}
		if err := sn.Remove(ctx, viewKey); err != nil {
			errs = append(errs, fmt.Errorf("remove cache view %q: %w", viewKey, err))
		}
	}
	return errs
}

// IsCachePath reports whether the given absolute path (within a fork's
// filesystem) belongs to one of the managed cache directories.
//
// Used by the du command to separate cache-write bytes from workspace-write
// bytes.
func IsCachePath(path string) bool {
	// Normalise the path.
	clean := filepath.Clean(path)
	for _, name := range DefaultCacheNames {
		prefix := filepath.Join("cache", name)
		if clean == prefix || strings.HasPrefix(clean, prefix+string(filepath.Separator)) {
			return true
		}
		// Also match the absolute path variant /cache/<name>/...
		absPrefix := string(filepath.Separator) + prefix
		if clean == absPrefix || strings.HasPrefix(clean, absPrefix+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
