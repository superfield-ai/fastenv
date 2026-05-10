// Package mounter mounts a fork's overlayfs snapshot at a stable host path
// so that external processes (e.g. virtiofsd for Firecracker VM workspace
// sharing) can access the full merged filesystem view.
//
// # Design
//
// containerd's snapshot Prepare API returns a set of mount descriptors (type,
// source, options) but does not apply them automatically. To expose the merged
// overlayfs view to a non-container process, the mounts must be applied at an
// explicit target directory using the standard mount(2) syscall.
//
// This package creates the target directory under /run/fastenv/mounts/<forkKey>
// and calls mount.All() with the descriptors returned by the snapshotter.
// The caller is responsible for calling Unmount() when the mount is no longer
// needed (i.e. after the consuming process — virtiofsd — has been stopped and
// the fork is about to be discarded).
//
// # Required privileges
//
// mount(2) on Linux requires CAP_SYS_ADMIN or root. This is consistent with
// the rest of fastenv, which already requires root or containerd group
// membership to access the containerd socket.
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 4 (mount-path subcommand)
//   - docs/scout/phase1-findings.md §1 Phase B (snapshot Prepare / Mounts)
//   - https://github.com/superfield-ai/superfield-cli-ts — Firecracker CI runner
//     that consumes this path via virtiofsd
package mounter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/mount"

	"github.com/superfield-ai/fastenv/internal/snapshotter"
)

const mountRoot = "/run/fastenv/mounts"

// Options configures the mounter.
type Options struct {
	SocketPath string
	Namespace  string
}

// Result is returned by Mount on success.
type Result struct {
	// MountPath is the host directory where the fork's merged filesystem is
	// mounted. Pass this as sharedDir to virtiofsd.
	MountPath string `json:"mount_path"`
	// ForkKey is the fork identifier that was mounted.
	ForkKey string `json:"fork_key"`
}

// Mount mounts the overlayfs snapshot for forkKey at /run/fastenv/mounts/<forkKey>
// and returns the target path. Callers must call Unmount(forkKey) when done.
func Mount(ctx context.Context, forkKey string, opts Options) (Result, error) {
	sn, err := snapshotter.New("overlayfs", opts.SocketPath, opts.Namespace)
	if err != nil {
		return Result{}, fmt.Errorf("mounter: snapshotter: %w", err)
	}
	defer sn.Close()

	mounts, err := sn.Mounts(ctx, forkKey)
	if err != nil {
		return Result{}, fmt.Errorf("mounter: mounts for %q: %w", forkKey, err)
	}

	targetDir := filepath.Join(mountRoot, forkKey)
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("mounter: create target dir %q: %w", targetDir, err)
	}

	if err := mount.All(mounts, targetDir); err != nil {
		_ = os.Remove(targetDir)
		return Result{}, fmt.Errorf("mounter: mount overlayfs at %q: %w", targetDir, err)
	}

	return Result{MountPath: targetDir, ForkKey: forkKey}, nil
}

// Unmount removes the overlayfs mount at /run/fastenv/mounts/<forkKey> and
// deletes the directory. Best-effort: errors are returned but do not indicate
// data loss since the mount is read-only from the host's perspective.
func Unmount(forkKey string) error {
	targetDir := filepath.Join(mountRoot, forkKey)
	if err := mount.UnmountAll(targetDir, 0); err != nil {
		return fmt.Errorf("mounter: unmount %q: %w", targetDir, err)
	}
	if err := os.Remove(targetDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("mounter: remove %q: %w", targetDir, err)
	}
	return nil
}
