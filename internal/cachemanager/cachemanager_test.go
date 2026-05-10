// Package cachemanager_test tests the cachemanager package.
//
// These tests exercise the pure, non-containerd-dependent functions:
// key derivation, path classification, and copyDir/copyFile helpers.
// Functions that require a live containerd daemon are tested in integration
// tests via testutil.RequireContainerd.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 5 (shared caches)
package cachemanager_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/superfield-ai/fastenv/internal/cachemanager"
)

// TestCacheSnapshotKey verifies that CacheSnapshotKey produces the expected
// key format used to look up cache layers at fork time.
func TestCacheSnapshotKey(t *testing.T) {
	tests := []struct {
		imageName string
		cacheName string
		want      string
	}{
		{"my-workspace", "pip", "my-workspace:cache:pip"},
		{"my-workspace", "npm", "my-workspace:cache:npm"},
		{"my-workspace", "cargo", "my-workspace:cache:cargo"},
		{"project:latest", "pip", "project:latest:cache:pip"},
	}
	for _, tc := range tests {
		got := cachemanager.CacheSnapshotKey(tc.imageName, tc.cacheName)
		if got != tc.want {
			t.Errorf("CacheSnapshotKey(%q, %q) = %q, want %q",
				tc.imageName, tc.cacheName, got, tc.want)
		}
	}
}

// TestCacheViewKey verifies that CacheViewKey produces the expected key format
// used to look up per-fork cache view snapshots.
func TestCacheViewKey(t *testing.T) {
	tests := []struct {
		forkID    string
		cacheName string
		want      string
	}{
		{"agent-1", "pip", "agent-1:cacheview:pip"},
		{"agent-1", "npm", "agent-1:cacheview:npm"},
		{"fork-abc-123", "cargo", "fork-abc-123:cacheview:cargo"},
	}
	for _, tc := range tests {
		got := cachemanager.CacheViewKey(tc.forkID, tc.cacheName)
		if got != tc.want {
			t.Errorf("CacheViewKey(%q, %q) = %q, want %q",
				tc.forkID, tc.cacheName, got, tc.want)
		}
	}
}

// TestIsCachePath verifies that IsCachePath correctly classifies paths as
// managed cache paths or workspace paths.
func TestIsCachePath(t *testing.T) {
	cachePaths := []string{
		"cache/pip",
		"cache/pip/",
		"cache/pip/requests-2.31.0.tar.gz",
		"cache/npm/lodash-4.17.21.tgz",
		"cache/cargo/registry/src/github.com-1ecc6299db9ec823",
		"/cache/pip",
		"/cache/pip/something",
		"/cache/npm",
	}
	for _, p := range cachePaths {
		if !cachemanager.IsCachePath(p) {
			t.Errorf("IsCachePath(%q) = false, want true", p)
		}
	}

	nonCachePaths := []string{
		"src/main.go",
		"src/cache/pip",         // not at root
		"workspace/cache/pip",   // not at root
		"cache",                 // the root cache dir itself — not a managed path
		"cache/other",           // not a known cache name
		"/home/user/.npmrc",
		"",
		".",
	}
	for _, p := range nonCachePaths {
		if cachemanager.IsCachePath(p) {
			t.Errorf("IsCachePath(%q) = true, want false", p)
		}
	}
}

// TestDefaultCacheNames verifies the well-known cache names are present.
func TestDefaultCacheNames(t *testing.T) {
	names := cachemanager.DefaultCacheNames
	want := map[string]bool{"npm": true, "pip": true, "cargo": true}
	for _, n := range names {
		delete(want, n)
	}
	if len(want) > 0 {
		t.Errorf("DefaultCacheNames missing: %v", want)
	}
}

// TestBuildCacheLayers_SkipsMissing verifies that BuildCacheLayers silently
// skips cache directories that don't exist in the source tree.
// This test does not require a live containerd daemon — it uses a nil content
// store and snapshotter, so it only works because all cache dirs are missing
// and the function returns early before touching those parameters.
func TestBuildCacheLayers_SkipsMissing(t *testing.T) {
	// Create a source dir with no cache/ subdirectory.
	sourceDir := t.TempDir()

	// BuildCacheLayers should return an empty result without error when all
	// cache dirs are absent.
	//
	// We pass nil for cs and sn; if the function tries to use them for any
	// absent-but-not-skipped path, it will panic (desired: we want to confirm
	// absent dirs are skipped before any storage calls).
	result, err := cachemanager.BuildCacheLayers(nil, nil, nil, sourceDir, "test-image", nil)
	if err != nil {
		t.Fatalf("BuildCacheLayers with no cache dirs: %v", err)
	}
	if len(result.Layers) != 0 {
		t.Errorf("expected 0 layers for empty source dir, got %d", len(result.Layers))
	}
}

// TestBuildCacheLayers_DetectsCacheDirs verifies that BuildCacheLayers
// attempts to process cache directories that do exist.
// Because we don't have a real containerd daemon, we just verify that the
// function tries to process the directory (it will fail at the snapshot step,
// but the error will mention the cache name, not "directory not found").
func TestBuildCacheLayers_DetectsCacheDirs(t *testing.T) {
	sourceDir := t.TempDir()

	// Create a minimal cache/pip directory.
	pipDir := filepath.Join(sourceDir, "cache", "pip")
	if err := os.MkdirAll(pipDir, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Write a dummy file.
	if err := os.WriteFile(filepath.Join(pipDir, "dummy.whl"), []byte("wheel"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// BuildCacheLayers will detect the pip dir and attempt to create a snapshot.
	// With nil cs/sn it will panic or return an error. We just check that the
	// detection logic works by verifying the error (or lack thereof when both
	// are nil indicates early return due to Stat returning err on nil snapshotter).
	//
	// Since sn is nil, sn.Stat will panic. We use a recover to detect the panic
	// which proves the function attempted to process the pip directory.
	defer func() {
		r := recover()
		// A nil-pointer panic means the function reached the snapshotter call,
		// confirming it detected the pip directory.
		if r == nil {
			t.Error("expected a nil-pointer panic from nil snapshotter, got none")
		}
	}()

	_, _ = cachemanager.BuildCacheLayers(nil, nil, nil, sourceDir, "test-image", nil)
}
