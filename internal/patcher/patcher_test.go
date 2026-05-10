// Package patcher_test tests the patcher package using filesystem fixtures.
//
// These tests do not require a containerd daemon. They build temporary upper
// directory trees and verify that ExportPatchFromUpperDir correctly generates
// unified diff patches for text files, deleted files, and binary files.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 4 (export-patch)
package patcher_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/superfield-ai/fastenv/internal/differ"
	"github.com/superfield-ai/fastenv/internal/patcher"
)

// makeFile creates a regular file with given content inside dir at relPath.
func makeFile(t *testing.T, dir, relPath string, content []byte) {
	t.Helper()
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, content, 0o644); err != nil {
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
	if err := syscall.Mknod(full, syscall.S_IFCHR|0o600, 0); err != nil {
		t.Skipf("mknod requires root or CAP_MKNOD — skipping whiteout test: %v", err)
	}
}

func TestExportPatch_TextFile(t *testing.T) {
	upper := t.TempDir()
	makeFile(t, upper, "workspace/hello.txt", []byte("hello world\n"))

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}

	var buf bytes.Buffer
	var warnBuf bytes.Buffer
	err = patcher.ExportPatchFromUpperDir(upper, entries, &buf, patcher.Options{Stderr: &warnBuf})
	if err != nil {
		t.Fatalf("ExportPatchFromUpperDir: %v", err)
	}

	patch := buf.String()

	// Must contain unified diff header.
	if !strings.Contains(patch, "diff --git a/workspace/hello.txt b/workspace/hello.txt") {
		t.Errorf("patch missing diff header:\n%s", patch)
	}
	if !strings.Contains(patch, "--- /dev/null") {
		t.Errorf("patch missing --- /dev/null:\n%s", patch)
	}
	if !strings.Contains(patch, "+++ b/workspace/hello.txt") {
		t.Errorf("patch missing +++ b/workspace/hello.txt:\n%s", patch)
	}
	if !strings.Contains(patch, "+hello world") {
		t.Errorf("patch missing +hello world line:\n%s", patch)
	}
	// No binary warning.
	if warnBuf.Len() > 0 {
		t.Errorf("unexpected warning for text file: %s", warnBuf.String())
	}
}

func TestExportPatch_DeletedFile(t *testing.T) {
	upper := t.TempDir()
	makeWhiteout(t, upper, "deleted.cfg")

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}

	var buf bytes.Buffer
	var warnBuf bytes.Buffer
	err = patcher.ExportPatchFromUpperDir(upper, entries, &buf, patcher.Options{Stderr: &warnBuf})
	if err != nil {
		t.Fatalf("ExportPatchFromUpperDir: %v", err)
	}

	patch := buf.String()

	if !strings.Contains(patch, "diff --git a/deleted.cfg b/deleted.cfg") {
		t.Errorf("patch missing diff header for deleted file:\n%s", patch)
	}
	if !strings.Contains(patch, "deleted file mode") {
		t.Errorf("patch missing 'deleted file mode' for deleted file:\n%s", patch)
	}
	if !strings.Contains(patch, "+++ /dev/null") {
		t.Errorf("patch missing '+++ /dev/null' for deleted file:\n%s", patch)
	}
}

func TestExportPatch_WhdotPrefixDeletedFile(t *testing.T) {
	upper := t.TempDir()
	// OCI whiteout convention: .wh. prefix indicates deleted file.
	makeFile(t, upper, ".wh.removed.txt", []byte(""))

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}

	var buf bytes.Buffer
	err = patcher.ExportPatchFromUpperDir(upper, entries, &buf, patcher.Options{Stderr: os.Stderr})
	if err != nil {
		t.Fatalf("ExportPatchFromUpperDir: %v", err)
	}

	patch := buf.String()

	if !strings.Contains(patch, "deleted file mode") {
		t.Errorf("patch missing 'deleted file mode' for .wh. whiteout:\n%s", patch)
	}
	if !strings.Contains(patch, "removed.txt") {
		t.Errorf("patch should reference 'removed.txt', not '.wh.removed.txt':\n%s", patch)
	}
}

func TestExportPatch_BinaryFileSkippedByDefault(t *testing.T) {
	upper := t.TempDir()
	// A file with NUL bytes is binary.
	binaryContent := []byte{0x00, 0x01, 0x02, 0x03, 0xFF}
	makeFile(t, upper, "image.bin", binaryContent)

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}

	var buf bytes.Buffer
	var warnBuf bytes.Buffer
	err = patcher.ExportPatchFromUpperDir(upper, entries, &buf, patcher.Options{
		IncludeBinary: false,
		Stderr:        &warnBuf,
	})
	if err != nil {
		t.Fatalf("ExportPatchFromUpperDir: %v", err)
	}

	// Patch should be empty (binary file skipped).
	if buf.Len() > 0 {
		t.Errorf("expected empty patch for skipped binary, got:\n%s", buf.String())
	}
	// Warning should be emitted.
	if !strings.Contains(warnBuf.String(), "warning: skipping binary file") {
		t.Errorf("expected binary warning, got: %q", warnBuf.String())
	}
	if !strings.Contains(warnBuf.String(), "image.bin") {
		t.Errorf("warning should name the binary file, got: %q", warnBuf.String())
	}
}

func TestExportPatch_BinaryFileIncluded(t *testing.T) {
	upper := t.TempDir()
	binaryContent := []byte{0x00, 0x01, 0x02, 0x03, 0xFF}
	makeFile(t, upper, "image.bin", binaryContent)

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}

	var buf bytes.Buffer
	var warnBuf bytes.Buffer
	err = patcher.ExportPatchFromUpperDir(upper, entries, &buf, patcher.Options{
		IncludeBinary: true,
		Stderr:        &warnBuf,
	})
	if err != nil {
		t.Fatalf("ExportPatchFromUpperDir: %v", err)
	}

	patch := buf.String()

	// With IncludeBinary=true, the patch must include the binary patch section.
	if !strings.Contains(patch, "diff --git a/image.bin b/image.bin") {
		t.Errorf("patch missing diff header for binary file:\n%s", patch)
	}
	if !strings.Contains(patch, "GIT binary patch") {
		t.Errorf("patch missing 'GIT binary patch' header:\n%s", patch)
	}
	// No warnings.
	if warnBuf.Len() > 0 {
		t.Errorf("unexpected warning when IncludeBinary=true: %s", warnBuf.String())
	}
}

func TestExportPatch_EmptyUpperDir(t *testing.T) {
	upper := t.TempDir()

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}

	var buf bytes.Buffer
	err = patcher.ExportPatchFromUpperDir(upper, entries, &buf, patcher.Options{Stderr: os.Stderr})
	if err != nil {
		t.Fatalf("ExportPatchFromUpperDir: %v", err)
	}

	// Empty upper dir → empty patch.
	if buf.Len() != 0 {
		t.Errorf("expected empty patch for empty upper dir, got:\n%s", buf.String())
	}
}

func TestExportPatch_MultipleFiles(t *testing.T) {
	upper := t.TempDir()
	makeFile(t, upper, "a.txt", []byte("line a\n"))
	makeFile(t, upper, "sub/b.txt", []byte("line b\n"))

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}

	var buf bytes.Buffer
	err = patcher.ExportPatchFromUpperDir(upper, entries, &buf, patcher.Options{Stderr: os.Stderr})
	if err != nil {
		t.Fatalf("ExportPatchFromUpperDir: %v", err)
	}

	patch := buf.String()

	if !strings.Contains(patch, "a.txt") {
		t.Errorf("patch missing a.txt:\n%s", patch)
	}
	if !strings.Contains(patch, "sub/b.txt") {
		t.Errorf("patch missing sub/b.txt:\n%s", patch)
	}
}

func TestExportPatch_EmptyTextFile(t *testing.T) {
	upper := t.TempDir()
	makeFile(t, upper, "empty.txt", []byte(""))

	entries, err := differ.DiffFromUpperDir(upper)
	if err != nil {
		t.Fatalf("DiffFromUpperDir: %v", err)
	}

	var buf bytes.Buffer
	err = patcher.ExportPatchFromUpperDir(upper, entries, &buf, patcher.Options{Stderr: os.Stderr})
	if err != nil {
		t.Fatalf("ExportPatchFromUpperDir: %v", err)
	}

	patch := buf.String()

	// Should contain the diff header even for an empty file.
	if !strings.Contains(patch, "diff --git a/empty.txt b/empty.txt") {
		t.Errorf("patch missing diff header for empty file:\n%s", patch)
	}
}
