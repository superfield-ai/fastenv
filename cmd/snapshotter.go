// snapshotter.go — helper for constructing the snapshotter driver from CLI flags.
//
// This file provides newSnapshotter(), a shared helper used by subcommands
// that perform snapshot operations. It translates the global --snapshotter,
// --socket, and --namespace flags into a ready-to-use snapshotter.Snapshotter
// instance.
//
// If the user passes an unregistered driver name, newSnapshotter returns a
// descriptive error (wrapping snapshotter.ErrUnknownDriver) instead of
// panicking. This satisfies the acceptance criterion from issue #3:
//
//	"Swapping --snapshotter to an unimplemented value returns a clear error
//	 rather than a panic."
//
// Canonical docs:
//   - docs/architecture.md §2 (pluggable snapshotter)
//   - docs/implementation-plan.md Phase 2 (--snapshotter flag)
package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/superfield-ai/fastenv/internal/snapshotter"
)

// newSnapshotter constructs the snapshotter driver selected by the global
// --snapshotter flag. It returns a user-friendly error when the driver name
// is unknown or when the driver cannot connect (e.g. containerd not running).
//
// The caller is responsible for calling Close() on the returned Snapshotter.
func newSnapshotter() (snapshotter.Snapshotter, error) {
	sn, err := snapshotter.New(snapshotterName, containerdSocket, containerdNamespace)
	if err != nil {
		if errors.Is(err, snapshotter.ErrUnknownDriver) {
			// Wrap the original error (preserving ErrUnknownDriver in the chain)
			// while adding a human-friendly hint about valid driver names.
			return nil, fmt.Errorf(
				"unknown snapshotter %q (available: %s): %w",
				snapshotterName,
				strings.Join(snapshotter.Drivers(), ", "),
				err,
			)
		}
		return nil, fmt.Errorf("snapshotter %q: %w", snapshotterName, err)
	}
	return sn, nil
}
