// Package differ_test tests the differ package using filesystem fixtures.
//
// These tests do not require a containerd daemon. They build temporary upper
// directory trees and verify that DiffFromUpperDir correctly classifies entries.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 4 (diff)
package differ_test

import (
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"

	"github.com/containerd/containerd/v2/core/mount"

	"github.com/superfield-ai/fastenv/internal/differ"
)

// makeDir creates a directory structure for testing.
func makeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

// makeFile creates a regular file with given content inside dir at relPath.
func makeFile(t *testing.T, dir, relPath, content string) {
	t.Helper()
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

// makeWhiteout creates an overlayfs whiteout at relPath (character device, rdev=0).
func makeWhiteout(t *testing.T, dir, relPath string) {
	t.Helper()
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	// mknod creates a character device with major=0, minor=0 (rdev=0).
	if err := syscall.Mknod(full, syscall.S_IFCHR|0o600, 0); err != nil {
		t.Skipf("mknod requires root or CAP_MKNOD — skipping whiteout test: %v", err)
	}
}

// sortEntries sorts DiffEntry slices by Path for deterministic comparisons.
func sortEntries(entries []differ.DiffEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
}

func TestDiffFromUpperDir_AddedFile(t *testing.T) {
	upper := makeDir(t)
	makeFile(t, upper, "workspace/newfile.txt", "hello")

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d: %v", len(entries), entries)
	}
	e := entries[0]
	if e.Path != "/workspace/newfile.txt" {
		t.Errorf("path: got %q, want %q", e.Path, "/workspace/newfile.txt")
	}
	if e.Status != "A" {
		t.Errorf("status: got %q, want %q", e.Status, "A")
	}
	if e.Size != int64(len("hello")) {
		t.Errorf("size: got %d, want %d", e.Size, len("hello"))
	}
}

func TestDiffFromUpperDir_MultipleFiles(t *testing.T) {
	upper := makeDir(t)
	makeFile(t, upper, "a.txt", "aaa")
	makeFile(t, upper, "sub/b.txt", "bb")
	makeFile(t, upper, "sub/c.txt", "c")

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}
	sortEntries(entries)

	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d: %v", len(entries), entries)
	}

	want := []struct {
		path   string
		status string
		size   int64
	}{
		{"/a.txt", "A", 3},
		{"/sub/b.txt", "A", 2},
		{"/sub/c.txt", "A", 1},
	}
	for i, w := range want {
		if entries[i].Path != w.path {
			t.Errorf("[%d] path: got %q, want %q", i, entries[i].Path, w.path)
		}
		if entries[i].Status != w.status {
			t.Errorf("[%d] status: got %q, want %q", i, entries[i].Status, w.status)
		}
		if entries[i].Size != w.size {
			t.Errorf("[%d] size: got %d, want %d", i, entries[i].Size, w.size)
		}
	}
}

func TestDiffFromUpperDir_WhiteoutCharDevice(t *testing.T) {
	upper := makeDir(t)
	makeWhiteout(t, upper, "deleted.txt")

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d: %v", len(entries), entries)
	}
	e := entries[0]
	if e.Path != "/deleted.txt" {
		t.Errorf("path: got %q, want %q", e.Path, "/deleted.txt")
	}
	if e.Status != "D" {
		t.Errorf("status: got %q, want %q", e.Status, "D")
	}
	if e.Size != 0 {
		t.Errorf("size: got %d, want 0", e.Size)
	}
}

func TestDiffFromUpperDir_WhiteoutDotPrefix(t *testing.T) {
	upper := makeDir(t)
	// OCI-convention .wh.-prefixed whiteout file.
	makeFile(t, upper, ".wh.removed.cfg", "")

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d: %v", len(entries), entries)
	}
	e := entries[0]
	if e.Path != "/removed.cfg" {
		t.Errorf("path: got %q, want %q", e.Path, "/removed.cfg")
	}
	if e.Status != "D" {
		t.Errorf("status: got %q, want %q", e.Status, "D")
	}
}

func TestDiffFromUpperDir_OpaqueMarkerSkipped(t *testing.T) {
	upper := makeDir(t)
	makeFile(t, upper, ".wh..wh..opq", "") // opaque dir marker — must be skipped
	makeFile(t, upper, "real.txt", "real")

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}

	// Only real.txt should appear; the opaque marker must be silently skipped.
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d: %v", len(entries), entries)
	}
	if entries[0].Path != "/real.txt" {
		t.Errorf("path: got %q, want /real.txt", entries[0].Path)
	}
}

func TestDiffFromUpperDir_EmptyUpperDir(t *testing.T) {
	upper := makeDir(t)

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("want 0 entries for empty upper dir, got %d: %v", len(entries), entries)
	}
}

func TestDiffFromUpperDir_DirectoriesNotReported(t *testing.T) {
	upper := makeDir(t)
	// Create a subdirectory with no files in it.
	if err := os.MkdirAll(filepath.Join(upper, "emptydir"), 0o755); err != nil {
		t.Fatal(err)
	}

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("want 0 entries (dirs not reported), got %d: %v", len(entries), entries)
	}
}

func TestUpperDir_ParsesFromMountOptions(t *testing.T) {
	mounts := []mount.Mount{
		{
			Type:   "overlay",
			Source: "overlay",
			Options: []string{
				"workdir=/var/lib/containerd/snapshots/42/work",
				"upperdir=/var/lib/containerd/snapshots/42/fs",
				"lowerdir=/var/lib/containerd/snapshots/1/fs",
			},
		},
	}

	got, err := differ.UpperDir(mounts)
	if err != nil {
		t.Fatalf("UpperDir: %v", err)
	}
	want := "/var/lib/containerd/snapshots/42/fs"
	if got != want {
		t.Errorf("UpperDir: got %q, want %q", got, want)
	}
}

func TestUpperDir_ErrorWhenMissing(t *testing.T) {
	// A read-only (committed) snapshot has no upperdir in its mount options.
	mounts := []mount.Mount{
		{
			Type:   "overlay",
			Source: "overlay",
			Options: []string{
				"lowerdir=/var/lib/containerd/snapshots/1/fs",
				"ro",
			},
		},
	}
	_, err := differ.UpperDir(mounts)
	if err == nil {
		t.Fatal("expected error when upperdir is missing, got nil")
	}
}
