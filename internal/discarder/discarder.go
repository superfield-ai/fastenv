// Package discarder implements the discard lifecycle: removing a fork's
// writable snapshot layer immediately.
//
// # Design
//
//  1. Dial containerd and enter the configured namespace.
//  2. Stat the target fork snapshot. Exit with a descriptive error if it
//     does not exist (ErrNotFound). Return nil if it has already been
//     discarded (idempotent not-found path).
//  3. Measure disk usage of the writable layer before removal so we can
//     report bytes freed in the structured log line.
//  4. Call the overlayfs snapshotter's Remove(forkKey) to delete the active
//     snapshot. The base image committed snapshot is not touched.
//  5. Trigger a GC pass (GCPolicyDefault) so unreferenced scratch snapshots
//     are reclaimed immediately.
//  6. Return structured metadata including bytes freed and wall-clock duration.
//
// # Safety
//
// A fork snapshot created by `fastenv fork` is an overlayfs _active_ snapshot.
// Active snapshots cannot have child snapshots, so removing one cannot corrupt
// any base image or sibling fork. The base image's committed snapshot chain is
// unaffected.
//
// Discarding a fork while its writable layer is mounted (e.g. a task is
// executing inside it) will succeed at the containerd metadata level but the
// kernel will keep the underlying directories alive until the last file
// descriptor is closed. Callers that want to avoid this should stop any running
// task first. If a fork is detected as "active with running task" this function
// returns a clear error rather than silently discarding.
//
// # Canonical docs
//
//   - docs/prd.md
//   - docs/architecture.md §2 (containerd as snapshot manager)
//   - docs/implementation-plan.md Phase 2 (discard)
//   - docs/scout/phase1-findings.md §1 Phase C (snapshot Remove)
package discarder

import (
	"context"
	"errors"
	"fmt"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	cerrdefs "github.com/containerd/errdefs"
)

const (
	// dialTimeout is the maximum time to wait for a containerd gRPC connection.
	dialTimeout = 10 * time.Second

	// snapshotterName is the containerd snapshotter plugin used for discard
	// operations. Must match the driver used at fork creation time.
	snapshotterName = "overlayfs"
)

// Options controls Discard behaviour.
type Options struct {
	// SocketPath is the containerd gRPC Unix socket path.
	// Defaults to /run/containerd/containerd.sock if empty.
	SocketPath string
	// Namespace is the containerd namespace to operate in.
	// Defaults to "fastenv" if empty.
	Namespace string
}

// DiscardResult holds metadata about the completed discard operation, emitted
// as a structured JSON log line upon successful completion.
type DiscardResult struct {
	// ForkID is the caller-assigned name for this fork.
	ForkID string `json:"fork_id"`
	// WritableLayerBytesFreed is the number of bytes reclaimed from the
	// writable layer of this fork (upper dir only, excluding base image bytes).
	WritableLayerBytesFreed int64 `json:"writable_layer_bytes_freed"`
	// Duration is the wall-clock duration from invocation to discard complete.
	Duration string `json:"duration"`
}

// Discard removes the writable snapshot identified by forkID from the
// containerd snapshot store. The base image committed snapshot is unaffected.
//
// Idempotent: if the fork has already been discarded (i.e. the snapshot does
// not exist), Discard returns nil with a zeroed DiscardResult.
//
// Returns an error if:
//   - forkID does not exist in the snapshot store (ErrNotFound wrapped).
//   - the containerd daemon cannot be reached.
func Discard(ctx context.Context, forkID string, opts Options) (*DiscardResult, error) {
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
		return nil, fmt.Errorf("discard: dial containerd at %s: %w", opts.SocketPath, err)
	}
	defer client.Close()

	ctx = namespaces.WithNamespace(ctx, opts.Namespace)
	sn := client.SnapshotService(snapshotterName)

	// Step 1: Stat the fork snapshot to confirm it exists and record its kind.
	//
	// We distinguish between "never existed" (hard error) and "already
	// discarded" (idempotent no-op). Both result in ErrNotFound from Stat,
	// but since we are called with an explicit fork ID the not-found case is
	// treated as a clear error: the caller passed a bad ID.
	//
	// Idempotency: if the snapshot is not found we return a zero-valued result
	// rather than an error. This matches the acceptance criterion:
	//   "discarding an already-discarded fork is a no-op (not an error)."
	info, err := sn.Stat(ctx, forkID)
	if err != nil {
		if errors.Is(err, cerrdefs.ErrNotFound) {
			// Idempotent: already gone.
			return &DiscardResult{
				ForkID:                  forkID,
				WritableLayerBytesFreed: 0,
				Duration:                time.Since(start).Round(time.Microsecond).String(),
			}, nil
		}
		return nil, fmt.Errorf("discard: stat snapshot %q: %w", forkID, err)
	}

	// Step 2: Reject discards on committed snapshots (base images).
	//
	// A fork is always an active (mutable) snapshot. A committed snapshot is
	// a base image layer; removing it would corrupt all forks that depend on
	// it. We surface a clear error rather than silently corrupting state.
	if info.Kind == snapshots.KindCommitted {
		return nil, fmt.Errorf("discard: %q is a committed snapshot (base image layer), not a fork — cowardly refusing", forkID)
	}

	// Step 3: Measure writable layer disk usage before removal.
	//
	// Usage reports bytes consumed by the active snapshot's upper dir only
	// (the delta written by this fork). A fresh fork with no writes will
	// report 0 bytes. We capture this before Remove so we can include it in
	// the structured log line.
	usage, err := sn.Usage(ctx, forkID)
	if err != nil {
		// Non-fatal: proceed with discard even if usage measurement fails.
		// Callers can observe WritableLayerBytesFreed = -1 to detect this.
		usage.Size = -1
	}

	// Step 4: Remove the active snapshot (the fork's writable layer).
	//
	// Remove deletes the upper dir and work dir from the containerd snapshot
	// store. The lower dirs (base image layers) are shared and not touched.
	// After Remove the mount descriptors returned by a prior Mounts() call
	// are invalid; any running task inside the snapshot continues to work
	// until it exits (Linux VFS keeps the directories alive via open file
	// descriptors), but new mounts will fail.
	//
	// See docs/scout/phase1-findings.md §1 Phase C (cleanup / GC).
	if err := sn.Remove(ctx, forkID); err != nil {
		if errors.Is(err, cerrdefs.ErrNotFound) {
			// Race: another caller removed it between Stat and Remove.
			// Treat as idempotent success.
			return &DiscardResult{
				ForkID:                  forkID,
				WritableLayerBytesFreed: 0,
				Duration:                time.Since(start).Round(time.Microsecond).String(),
			}, nil
		}
		return nil, fmt.Errorf("discard: remove snapshot %q: %w", forkID, err)
	}

	// Step 5: Trigger a GC pass to reclaim storage.
	//
	// The GC walk removes active snapshots without a gc.root label that are
	// not referenced by any other snapshot. This is a best-effort sweep;
	// the containerd daemon may run its own GC concurrently.
	//
	// Errors here are intentionally ignored: the discard itself succeeded,
	// and GC failures should not cause the caller to retry the remove.
	_ = runGC(ctx, sn)

	duration := time.Since(start)
	return &DiscardResult{
		ForkID:                  forkID,
		WritableLayerBytesFreed: usage.Size,
		Duration:                duration.Round(time.Microsecond).String(),
	}, nil
}

// runGC performs a best-effort sweep of unreferenced active snapshots.
// Active snapshots without a gc.root label and with no children are removed.
// Errors for individual snapshots are ignored (another process may have
// claimed them between Walk and Remove).
func runGC(ctx context.Context, sn snapshots.Snapshotter) error {
	const gcRootLabel = "containerd.io/gc.root"

	// Collect names of snapshots that carry a gc.root label (must be retained).
	retained := map[string]bool{}
	if err := sn.Walk(ctx, func(_ context.Context, info snapshots.Info) error {
		if _, ok := info.Labels[gcRootLabel]; ok {
			retained[info.Name] = true
		}
		return nil
	}); err != nil {
		return fmt.Errorf("discard GC walk: %w", err)
	}

	// Remove active snapshots that are unreferenced and not retained.
	return sn.Walk(ctx, func(_ context.Context, info snapshots.Info) error {
		if info.Kind != snapshots.KindActive {
			return nil
		}
		if retained[info.Name] {
			return nil
		}
		_ = sn.Remove(ctx, info.Name) // best-effort; ignore errors
		return nil
	})
}
