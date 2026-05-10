// overlayfs.go — overlayfs-backed Snapshotter implementation.
//
// This file registers the "overlayfs" driver and provides a concrete
// implementation of the Snapshotter interface backed by containerd's built-in
// overlayfs snapshotter. It is the default driver in fastenv v1.
//
// # How overlayfs snapshots work
//
// Each snapshot is stored as a set of directories under containerd's snapshot
// root (typically /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs):
//
//   - lower dir(s): read-only layers from the parent chain
//   - upper dir: writable layer where writes land (empty at fork creation)
//   - work dir:  required by overlayfs for atomic rename semantics
//
// containerd manages these directories; fastenv only calls the high-level gRPC
// methods. The kernel overlayfs driver merges the layers into a unified view
// when the mount is active.
//
// # Integration notes from phase1-findings.md §1
//
//   - containerd Prepare(ctx, forkKey, baseKey) with an existing committed
//     base snapshot returns the overlayfs mount descriptors immediately. No
//     data is copied. Wall-clock cost is dominated by mkdir + mount syscalls
//     (expected sub-millisecond to single-digit millisecond).
//
//   - A committed snapshot must carry the "containerd.io/gc.root" label to
//     survive containerd's background GC during long-running sessions.
//
// # Canonical docs
//
//   - docs/architecture.md §2 (containerd as snapshot manager)
//   - docs/scout/phase1-findings.md §1 (snapshot call sequence)
//   - docs/implementation-plan.md Phase 2 (overlayfs driver)
package snapshotter

import (
	"context"
	"fmt"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

const (
	// gcRootLabel pins a committed snapshot so containerd GC does not reclaim
	// it while forks are alive. The value is an RFC 3339 timestamp (convention
	// used by containerd tooling).
	//
	// See: https://github.com/containerd/containerd/blob/main/docs/garbage-collection.md
	gcRootLabel = "containerd.io/gc.root"

	// dialTimeout is the maximum time to wait for a containerd gRPC connection.
	dialTimeout = 10 * time.Second
)

func init() {
	// Register the overlayfs driver so the main package can select it by
	// name via --snapshotter=overlayfs (the default).
	Register("overlayfs", newOverlayfs)
}

// overlayfsSnapshotter implements Snapshotter using containerd's overlayfs
// snapshotter plugin via the gRPC client API.
type overlayfsSnapshotter struct {
	client    *containerd.Client
	namespace string
}

// newOverlayfs is the ConstructorFunc for the "overlayfs" driver. It dials
// the containerd socket and returns a ready-to-use driver.
func newOverlayfs(socketPath, namespace string) (Snapshotter, error) {
	c, err := containerd.New(socketPath,
		containerd.WithDefaultNamespace(namespace),
		containerd.WithTimeout(dialTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("overlayfs snapshotter: dial containerd at %s: %w", socketPath, err)
	}
	return &overlayfsSnapshotter{client: c, namespace: namespace}, nil
}

// ctx injects the driver's containerd namespace into ctx so every API call
// lands in the correct namespace.
func (s *overlayfsSnapshotter) ctx(parent context.Context) context.Context {
	return namespaces.WithNamespace(parent, s.namespace)
}

// snapshotterClient returns the containerd snapshotter client scoped to the
// overlayfs plugin.
func (s *overlayfsSnapshotter) snapshotterClient() snapshots.Snapshotter {
	return s.client.SnapshotService("overlayfs")
}

// PrepareBase ensures that a committed snapshot identified by baseKey exists in
// the store. If it already exists the call is a no-op.
//
// In a full implementation this would pull the OCI image identified by
// imageRef and unpack its layers into a chain of committed snapshots whose
// final snapshot is named baseKey. In this phase we create a minimal empty
// committed snapshot so the interface contract is satisfied and downstream
// callers (Fork, Discard) can be exercised.
//
// TODO(Phase 3): pull the OCI image via containerd's image service, unpack
// each layer with diff.Apply, and commit each layer digest as a committed
// snapshot chained from the previous one.
func (s *overlayfsSnapshotter) PrepareBase(ctx context.Context, imageRef, baseKey string) error {
	ctx = s.ctx(ctx)
	sn := s.snapshotterClient()

	// Idempotency check: if the base snapshot already exists, return early.
	if _, err := sn.Stat(ctx, baseKey); err == nil {
		return nil // already prepared
	}

	// Prepare an active scratch snapshot (no parent → empty root fs).
	scratchKey := baseKey + "-scratch"
	_, err := sn.Prepare(ctx, scratchKey, "",
		snapshots.WithLabels(map[string]string{
			gcRootLabel: time.Now().UTC().Format(time.RFC3339),
		}),
	)
	if err != nil {
		return fmt.Errorf("overlayfs PrepareBase: prepare scratch: %w", err)
	}

	// Commit the scratch snapshot as the named base. The gc.root label is
	// carried forward from the Prepare opts above.
	if err := sn.Commit(ctx, baseKey, scratchKey,
		snapshots.WithLabels(map[string]string{
			gcRootLabel: time.Now().UTC().Format(time.RFC3339),
		}),
	); err != nil {
		// Best-effort cleanup of the scratch snapshot.
		_ = sn.Remove(ctx, scratchKey)
		return fmt.Errorf("overlayfs PrepareBase: commit: %w", err)
	}

	return nil
}

// Fork creates a writable active snapshot (forkKey) from the committed base
// snapshot (baseKey) using overlayfs copy-on-write semantics.
//
// On success the fork is ready for exec; no bytes are copied from the base.
// The mounts are not returned here — callers use Mounts(forkKey) to retrieve
// them when needed.
//
// Canonical docs:
//   - docs/scout/phase1-findings.md §1 Phase B (snapshot Prepare for fork)
func (s *overlayfsSnapshotter) Fork(ctx context.Context, baseKey, forkKey string) error {
	ctx = s.ctx(ctx)
	_, err := s.snapshotterClient().Prepare(ctx, forkKey, baseKey)
	if err != nil {
		return fmt.Errorf("overlayfs Fork: prepare %q from %q: %w", forkKey, baseKey, err)
	}
	return nil
}

// Mounts returns the overlayfs mount descriptors for the active snapshot
// identified by forkKey. The returned mounts are passed to a container runtime
// (crun) or to mount(8) to materialise the filesystem.
func (s *overlayfsSnapshotter) Mounts(ctx context.Context, forkKey string) ([]Mount, error) {
	ctx = s.ctx(ctx)
	mounts, err := s.snapshotterClient().Mounts(ctx, forkKey)
	if err != nil {
		return nil, fmt.Errorf("overlayfs Mounts %q: %w", forkKey, err)
	}
	return mounts, nil
}

// Usage returns disk-resource statistics for the active snapshot forkKey,
// excluding the parent chain.
func (s *overlayfsSnapshotter) Usage(ctx context.Context, forkKey string) (Usage, error) {
	ctx = s.ctx(ctx)
	u, err := s.snapshotterClient().Usage(ctx, forkKey)
	if err != nil {
		return Usage{}, fmt.Errorf("overlayfs Usage %q: %w", forkKey, err)
	}
	return u, nil
}

// Discard removes the active snapshot identified by forkKey from the store.
// The base snapshot is not affected.
//
// Canonical docs:
//   - docs/scout/phase1-findings.md §1 Phase C (cleanup / GC)
func (s *overlayfsSnapshotter) Discard(ctx context.Context, forkKey string) error {
	ctx = s.ctx(ctx)
	if err := s.snapshotterClient().Remove(ctx, forkKey); err != nil {
		return fmt.Errorf("overlayfs Discard %q: %w", forkKey, err)
	}
	return nil
}

// GC triggers garbage collection of unreferenced snapshots in the store.
//
// This implementation walks all snapshots in the namespace and removes any
// active snapshot that has no gc.root label and is not a parent of another
// snapshot. Committed snapshots with a gc.root label are retained.
//
// GCPolicyAggressive is reserved for a future phase and currently returns
// ErrNotImplemented.
//
// Note: containerd's daemon-side GC (triggered via the internal GC service)
// is more authoritative; this client-side implementation is a best-effort
// sweep suited for Phase 2. See docs/implementation-plan.md Phase 4 for the
// planned daemon-integrated GC path.
func (s *overlayfsSnapshotter) GC(ctx context.Context, policy GCPolicy) error {
	if policy == GCPolicyAggressive {
		return fmt.Errorf("overlayfs GC: %w: aggressive policy", ErrNotImplemented)
	}
	ctx = s.ctx(ctx)
	sn := s.snapshotterClient()

	// Collect all snapshot keys that carry a gc.root label (must be retained).
	retained := map[string]bool{}
	if err := sn.Walk(ctx, func(_ context.Context, info snapshots.Info) error {
		if _, ok := info.Labels[gcRootLabel]; ok {
			retained[info.Name] = true
		}
		return nil
	}); err != nil {
		return fmt.Errorf("overlayfs GC walk: %w", err)
	}

	// Remove active (mutable) snapshots that are not in the retained set.
	return sn.Walk(ctx, func(_ context.Context, info snapshots.Info) error {
		if info.Kind != snapshots.KindActive {
			return nil
		}
		if retained[info.Name] {
			return nil
		}
		if removeErr := sn.Remove(ctx, info.Name); removeErr != nil {
			// Log and continue rather than aborting the whole sweep.
			// A snapshot may have gained a reference between Walk and Remove.
			_ = removeErr
		}
		return nil
	})
}

// Close releases the containerd gRPC connection. Safe to call multiple times.
func (s *overlayfsSnapshotter) Close() error {
	if s.client == nil {
		return nil
	}
	return s.client.Close()
}
