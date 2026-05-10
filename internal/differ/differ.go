// Package differ enumerates files changed in a fork's overlayfs writable layer.
//
// # Design
//
// overlayfs stores writes from a fork in a dedicated "upper directory". Any
// file created or modified inside the fork lands in that directory, preserving
// the path relative to the filesystem root. Files deleted by the fork appear
// as character device files with major=0, minor=0 (overlayfs whiteout devices)
// at the same path.
//
// Diff walks the upper directory and classifies each entry:
//
//   - A (added):   regular file, symlink, or directory entry present in the
//     upper layer. This includes both newly created files and files from the
//     base that were modified (both land in upper; v1 does not distinguish them).
//   - D (deleted): character device with rdev==0 (overlayfs whiteout marker).
//     When a file is deleted inside the fork, the kernel creates a zero-device
//     char file at the same path in upper.
//
// The upper directory path is extracted from the overlay mount options returned
// by containerd's Mounts() call for the active snapshot:
//
//	mount.Options contains "upperdir=<path>"
//
// # Thread safety
//
// Diff is safe for concurrent calls. No shared state is mutated.
//
// # Canonical docs
//
//   - docs/prd.md
//   - docs/architecture.md §2 (containerd as snapshot manager)
//   - docs/implementation-plan.md Phase 4 (diff)
//   - docs/scout/phase1-findings.md §1 Phase B (snapshot Prepare, overlayfs mount options)
package differ

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

const (
	// dialTimeout is the maximum time to wait for a containerd gRPC connection.
	dialTimeout = 10 * time.Second

	// snapshotterName is the containerd snapshotter plugin used for fork operations.
	snapshotterName = "overlayfs"
)

// FileStatus classifies a changed file relative to the fork base.
type FileStatus byte

const (
	// StatusAdded means the file was created (or modified) in the fork's writable
	// layer. v1 maps both new and overwritten files to 'A' because the overlayfs
	// upper directory does not distinguish new files from overwrites without
	// consulting the base snapshot.
	StatusAdded FileStatus = 'A'

	// StatusDeleted means the file was deleted inside the fork. It appears as an
	// overlayfs whiteout: a character device with major=0, minor=0.
	StatusDeleted FileStatus = 'D'
)

// DiffEntry describes a single changed file in the fork's writable layer.
type DiffEntry struct {
	// Path is the absolute path of the file as it would appear inside the fork's
	// root filesystem (e.g. "/workspace/newfile.txt").
	Path string `json:"path"`

	// Status is the single-character classification: "A" (added) or "D" (deleted).
	Status string `json:"status"`

	// Size is the file size in bytes. Zero for whiteout (deleted) entries.
	Size int64 `json:"size"`
}

// Options controls Diff behaviour.
type Options struct {
	// SocketPath is the containerd gRPC Unix socket path.
	// Defaults to /run/containerd/containerd.sock if empty.
	SocketPath string

	// Namespace is the containerd namespace to operate in.
	// Defaults to "fastenv" if empty.
	Namespace string
}

// UpperDirFromFork connects to containerd and returns the upperdir path for the
// given forkID active snapshot. It is the lower-level companion to Diff for
// callers that need the upperdir path in addition to (or instead of) the entry
// list — for example, to read file content when generating a patch.
//
// Returns an error if:
//   - containerd cannot be reached.
//   - forkID does not exist as an active snapshot.
//   - the snapshot is not backed by overlayfs (upperdir not found in mount options).
func UpperDirFromFork(ctx context.Context, forkID string, opts Options) (string, error) {
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
		return "", fmt.Errorf("upperdir: dial containerd at %s: %w", opts.SocketPath, err)
	}
	defer client.Close()

	ctx = namespaces.WithNamespace(ctx, opts.Namespace)

	sn := client.SnapshotService(snapshotterName)
	mounts, err := sn.Mounts(ctx, forkID)
	if err != nil {
		return "", fmt.Errorf("upperdir: mounts for fork %q: %w", forkID, err)
	}

	upperDir, err := UpperDir(mounts)
	if err != nil {
		return "", fmt.Errorf("upperdir: fork %q: %w", forkID, err)
	}

	return upperDir, nil
}

// Diff returns the list of files changed in forkID's overlayfs writable layer.
//
// It retrieves the overlay mount descriptors from containerd, extracts the
// upperdir path, and walks the directory to produce a list of DiffEntry values.
// It does not require the fork to be idle — the upper directory is readable
// whether or not a container is currently running inside the fork.
//
// Returns an error if:
//   - containerd cannot be reached.
//   - forkID does not exist as an active snapshot.
//   - the snapshot is not backed by overlayfs (upperdir not found in mount options).
//   - the upper directory cannot be read.
func Diff(ctx context.Context, forkID string, opts Options) ([]DiffEntry, error) {
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
		return nil, fmt.Errorf("diff: dial containerd at %s: %w", opts.SocketPath, err)
	}
	defer client.Close()

	ctx = namespaces.WithNamespace(ctx, opts.Namespace)

	// Retrieve the mount descriptors for the active snapshot.
	// For an overlayfs active snapshot the options list includes:
	//   "workdir=<path>", "upperdir=<path>", "lowerdir=<path1>:<path2>:..."
	sn := client.SnapshotService(snapshotterName)
	mounts, err := sn.Mounts(ctx, forkID)
	if err != nil {
		return nil, fmt.Errorf("diff: mounts for fork %q: %w", forkID, err)
	}

	// Extract the upper directory from the mount options.
	upperDir, err := UpperDir(mounts)
	if err != nil {
		return nil, fmt.Errorf("diff: fork %q: %w", forkID, err)
	}

	return DiffFromUpperDir(upperDir)
}

// DiffFromUpperDir returns the list of changed files by walking an existing
// upperdir path directly. This is the lower-level entry point used by tests
// that prepare their own directory trees without a containerd daemon.
func DiffFromUpperDir(upperDir string) ([]DiffEntry, error) {
	return walkUpperDir(upperDir)
}

// UpperDir extracts the upperdir path from a slice of overlay mount descriptors.
//
// The overlayfs driver encodes the upper directory as a key=value option inside
// mount.Options: "upperdir=<path>". This function returns the extracted path or
// an error if no such option is found (indicating the snapshot is not an active
// overlayfs snapshot).
func UpperDir(mounts []mount.Mount) (string, error) {
	for _, m := range mounts {
		for _, opt := range m.Options {
			if strings.HasPrefix(opt, "upperdir=") {
				return strings.TrimPrefix(opt, "upperdir="), nil
			}
		}
	}
	return "", fmt.Errorf("upperdir not found in mount options: snapshot may not be an active overlayfs fork")
}

// walkUpperDir walks upperDir and returns a DiffEntry for each entry found.
//
// Whiteout files (character devices with rdev==0) are reported as StatusDeleted.
// All other non-directory entries are reported as StatusAdded.
// Directories themselves are traversed but not emitted as changed entries.
//
// The opaque directory marker file (.wh..wh..opq) is skipped silently.
func walkUpperDir(upperDir string) ([]DiffEntry, error) {
	var entries []DiffEntry

	err := filepath.WalkDir(upperDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk %s: %w", path, walkErr)
		}

		// The root of the upper directory itself is not a changed entry.
		if path == upperDir {
			return nil
		}

		// Compute the path as it appears inside the fork's root filesystem.
		rel, err := filepath.Rel(upperDir, path)
		if err != nil {
			return fmt.Errorf("rel path %s: %w", path, err)
		}
		absPath := "/" + rel

		// Skip the OCI/overlayfs opaque directory marker file.
		// It signals that a directory was recreated opaquely but is not itself
		// a user-visible changed file.
		if d.Name() == ".wh..wh..opq" {
			return nil
		}

		// Directories are traversed to discover changes within but are not
		// emitted as changed entries in their own right.
		if d.IsDir() {
			return nil
		}

		// Stat the file to inspect its mode and size.
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}

		// Detect overlayfs whiteout: character device (S_IFCHR) with rdev==0.
		// When a file is deleted inside the fork, the kernel overlayfs driver
		// creates a character device at the same path with major=0, minor=0.
		if isWhiteout(info) {
			entries = append(entries, DiffEntry{
				Path:   absPath,
				Status: string(StatusDeleted),
				Size:   0,
			})
			return nil
		}

		// Skip .wh.-prefixed whiteout files (OCI archive convention). containerd
		// may use these in the upper dir to represent deleted files.
		base := filepath.Base(path)
		if strings.HasPrefix(base, ".wh.") {
			// The original file name is the base without the .wh. prefix.
			dir := filepath.Dir(absPath)
			originalBase := base[len(".wh."):]
			origPath := filepath.Join(dir, originalBase)
			entries = append(entries, DiffEntry{
				Path:   origPath,
				Status: string(StatusDeleted),
				Size:   0,
			})
			return nil
		}

		// Regular file, symlink, or other non-directory non-whiteout entry.
		// Reported as Added (v1 does not distinguish new vs overwritten).
		entries = append(entries, DiffEntry{
			Path:   absPath,
			Status: string(StatusAdded),
			Size:   info.Size(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	return entries, nil
}

// isWhiteout reports whether info describes an overlayfs whiteout file.
// A whiteout is a character device (S_IFCHR) with device number 0 (both major
// and minor equal to 0). This is the kernel overlayfs convention for deleted
// files in the upper layer.
func isWhiteout(info fs.FileInfo) bool {
	// Both ModeDevice and ModeCharDevice must be set for a char device.
	if info.Mode()&os.ModeCharDevice == 0 || info.Mode()&os.ModeDevice == 0 {
		return false
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return sys.Rdev == 0
}
