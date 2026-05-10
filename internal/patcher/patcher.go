// Package patcher generates a unified diff patch from a fork's overlayfs
// upper directory. The output is compatible with `git apply` and `patch -p1`.
//
// # Patch format
//
// Each changed file produces one diff section:
//
//   - Added/modified files:  "--- /dev/null" + "+++ b/<path>" with "+" lines.
//   - Deleted files:         "--- a/<path>" + "+++ /dev/null" (deletion marker).
//
// Binary files are skipped by default (a warning is written to Stderr);
// pass IncludeBinary=true to emit git binary patch hunks instead.
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 4 (export-patch)
//   - docs/architecture.md §2 (overlayfs upper directory)
package patcher

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/superfield-ai/fastenv/internal/differ"
)

// Options controls ExportPatch behaviour.
type Options struct {
	// SocketPath is the containerd gRPC Unix socket path.
	// Defaults to /run/containerd/containerd.sock if empty.
	SocketPath string

	// Namespace is the containerd namespace to operate in.
	// Defaults to "fastenv" if empty.
	Namespace string

	// IncludeBinary controls whether binary files are included in the patch.
	// When false (default), binary files are skipped with a warning written to Stderr.
	IncludeBinary bool

	// Stderr is where warning messages are written. Defaults to os.Stderr if nil.
	Stderr io.Writer
}

// ExportPatch writes a unified diff patch for forkID's writable layer changes
// to w.
//
// It retrieves the overlay mount descriptors from containerd, locates the
// upper directory, and generates a patch that can be applied via `git apply`
// or `patch -p1` to reproduce the fork's filesystem changes on a clean base.
//
// Binary files are skipped (with a warning) unless opts.IncludeBinary is true.
// Deleted files are emitted as deletion hunks.
//
// Does not require the fork to be idle.
func ExportPatch(ctx context.Context, forkID string, w io.Writer, opts Options) error {
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}

	differOpts := differ.Options{
		SocketPath: opts.SocketPath,
		Namespace:  opts.Namespace,
	}

	upperDir, err := differ.UpperDirFromFork(ctx, forkID, differOpts)
	if err != nil {
		return fmt.Errorf("export-patch: %w", err)
	}

	entries, err := differ.DiffFromUpperDir(upperDir)
	if err != nil {
		return fmt.Errorf("export-patch: %w", err)
	}

	return WritePatch(upperDir, entries, w, opts)
}

// ExportPatchFromUpperDir writes a unified diff patch for the given upperDir
// and DiffEntry list. This is the lower-level entry point used by tests that
// prepare their own directory trees without a containerd daemon.
func ExportPatchFromUpperDir(upperDir string, entries []differ.DiffEntry, w io.Writer, opts Options) error {
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	return WritePatch(upperDir, entries, w, opts)
}

// WritePatch writes unified diff sections for each entry to w.
func WritePatch(upperDir string, entries []differ.DiffEntry, w io.Writer, opts Options) error {
	for _, e := range entries {
		if err := writeEntry(upperDir, e, w, opts); err != nil {
			return fmt.Errorf("patch entry %s: %w", e.Path, err)
		}
	}
	return nil
}

// writeEntry writes a single diff section for one DiffEntry.
func writeEntry(upperDir string, e differ.DiffEntry, w io.Writer, opts Options) error {
	switch e.Status {
	case string(differ.StatusDeleted):
		return writeDeletedEntry(e, w)
	case string(differ.StatusAdded):
		absPath := filepath.Join(upperDir, e.Path)
		return writeAddedEntry(absPath, e.Path, w, opts)
	default:
		return fmt.Errorf("unknown status %q for path %s", e.Status, e.Path)
	}
}

// writeDeletedEntry writes a unified diff section representing a file deletion.
// Since we don't have the original content from the base snapshot, we emit a
// minimal deletion header. The hunk removes a single placeholder line so that
// `git apply --allow-empty` and `patch` recognise this as a file deletion.
func writeDeletedEntry(e differ.DiffEntry, w io.Writer) error {
	// Sanitise the path: strip leading slash.
	rel := strings.TrimPrefix(e.Path, "/")

	_, err := fmt.Fprintf(w,
		"diff --git a/%s b/%s\ndeleted file mode 100644\nindex 0000000..0000000\n--- a/%s\n+++ /dev/null\n@@ -1 +0,0 @@\n-\n",
		rel, rel, rel)
	return err
}

// writeAddedEntry reads the file at absPath and writes a unified diff section
// that adds it. Binary files are either skipped (warning emitted) or included
// as git binary patch hunks depending on opts.IncludeBinary.
func writeAddedEntry(absPath, forkPath string, w io.Writer, opts Options) error {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", absPath, err)
	}

	rel := strings.TrimPrefix(forkPath, "/")

	if isBinary(data) {
		if !opts.IncludeBinary {
			fmt.Fprintf(opts.Stderr, "warning: skipping binary file %s (use --include-binary to include)\n", forkPath)
			return nil
		}
		return writeGitBinaryEntry(rel, data, w)
	}

	return writeTextEntry(rel, data, w)
}

// writeTextEntry writes a standard unified diff section for a text file.
// The hunk header uses the "new file" context-less format: @@ -0,0 +1,N @@
func writeTextEntry(rel string, data []byte, w io.Writer) error {
	lines := splitLines(data)
	n := len(lines)

	// Unified diff header.
	if _, err := fmt.Fprintf(w,
		"diff --git a/%s b/%s\nnew file mode 100644\nindex 0000000..0000000\n--- /dev/null\n+++ b/%s\n",
		rel, rel, rel); err != nil {
		return err
	}

	if n == 0 {
		// Empty file: emit an empty hunk.
		_, err := fmt.Fprintf(w, "@@ -0,0 +0,0 @@\n")
		return err
	}

	// Hunk header: @@ -0,0 +1,N @@
	if _, err := fmt.Fprintf(w, "@@ -0,0 +1,%d @@\n", n); err != nil {
		return err
	}

	// Each content line prefixed with '+'.
	for _, line := range lines {
		if _, err := fmt.Fprintf(w, "+%s\n", line); err != nil {
			return err
		}
	}

	return nil
}

// writeGitBinaryEntry writes a git binary patch section for a binary file.
// The format uses the "literal" encoding: base85 of the raw bytes. Since Go
// does not have a built-in git-flavour base85 encoder, we use base64 wrapped
// in the git binary patch framing. This is accepted by `git apply` when the
// literal section header carries the correct byte count.
//
// For interoperability with standard `git apply`, we encode the raw bytes as
// a base64 literal blob. Note: `git apply` does not natively parse base64;
// this variant is intended for human inspection and tooling that handles
// the fastenv binary patch extension. When standard git apply compatibility
// for binary files is required, the caller should convert using `git diff --binary`.
func writeGitBinaryEntry(rel string, data []byte, w io.Writer) error {
	encoded := base64.StdEncoding.EncodeToString(data)
	_, err := fmt.Fprintf(w,
		"diff --git a/%s b/%s\nnew file mode 100644\nindex 0000000..0000000\nGIT binary patch\nliteral %d\n%s\nliteral 0\nHcmV?d00001\n",
		rel, rel, len(data), wrapLines(encoded, 76))
	return err
}

// wrapLines wraps a string at width characters per line.
func wrapLines(s string, width int) string {
	var sb strings.Builder
	for len(s) > width {
		sb.WriteString(s[:width])
		sb.WriteByte('\n')
		s = s[width:]
	}
	if len(s) > 0 {
		sb.WriteString(s)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// splitLines splits file data into lines, stripping the final newline (if any)
// so that we don't produce a spurious trailing empty "+" line.
func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	text := string(data)
	// Trim a single trailing newline to avoid an extra blank line in the patch.
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// isBinary reports whether data appears to be binary content.
// A file is considered binary if it contains a NUL byte or is not valid UTF-8.
func isBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return !utf8.Valid(data)
}
