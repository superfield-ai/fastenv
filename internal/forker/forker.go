// Package forker implements the fork lifecycle: creating a CoW writable
// snapshot from a named base image.
//
// # Design
//
//  1. Look up the named base image in containerd's image store.
//  2. Ensure the image's layers are unpacked into the overlayfs snapshotter
//     (idempotent: containerd skips layers that are already present).
//  3. Resolve the top-level committed snapshot key for the image by computing
//     the OCI chain ID of the layer chain.
//  4. Verify that forkID does not already exist (returns a clear error).
//  5. Call the overlayfs snapshotter's Prepare(forkID, baseSnapshotKey) to
//     allocate a new CoW writable snapshot. No data is copied.
//  6. Return structured metadata including creation latency.
//
// # Latency targets
//
// Fork creation must meet p50 ≤ 50ms and p95 ≤ 100ms wall-clock latency on a
// warm base image (layers already unpacked). Steps 1–4 are lightweight
// metadata reads. Step 5 is dominated by mkdir + mount syscalls; the overlayfs
// driver performs no I/O on base image bytes.
//
// # Canonical docs
//
//   - docs/prd.md
//   - docs/architecture.md §2 (containerd as snapshot manager)
//   - docs/implementation-plan.md Phase 2 (fork)
//   - docs/scout/phase1-findings.md §1 Phase B (snapshot Prepare for fork)
package forker

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

	// snapshotterName is the containerd snapshotter plugin used for fork
	// operations. overlayfs provides CoW semantics: the parent chain is mounted
	// read-only; each fork gets an independent empty upper dir for writes.
	snapshotterName = "overlayfs"
)

// Options controls Fork behaviour.
type Options struct {
	// SocketPath is the containerd gRPC Unix socket path.
	// Defaults to /run/containerd/containerd.sock if empty.
	SocketPath string
	// Namespace is the containerd namespace to operate in.
	// Defaults to "fastenv" if empty.
	Namespace string
}

// ForkResult holds metadata about the created fork, emitted as a structured
// JSON log line upon successful completion.
type ForkResult struct {
	// ForkID is the caller-assigned name for this fork.
	ForkID string `json:"fork_id"`
	// BaseImage is the name of the base image the fork was created from.
	BaseImage string `json:"base_image"`
	// SnapshotKey is the containerd snapshot key of the writable fork layer.
	// Equal to forkID: callers pass this key to the runtime or to Mounts().
	SnapshotKey string `json:"snapshot_key"`
	// CreationLatency is the wall-clock duration from invocation to fork ready.
	CreationLatency string `json:"creation_latency"`
}

// Fork creates a writable CoW snapshot identified by forkID from the base
// image named baseImage. The fork is ready immediately; no bytes are copied.
//
// Returns an error if:
//   - baseImage does not exist in containerd's image store.
//   - a snapshot with forkID already exists.
//   - the image layers cannot be unpacked.
func Fork(ctx context.Context, baseImage, forkID string, opts Options) (*ForkResult, error) {
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
		return nil, fmt.Errorf("fork: dial containerd at %s: %w", opts.SocketPath, err)
	}
	defer client.Close()

	ctx = namespaces.WithNamespace(ctx, opts.Namespace)

	// Step 1: Look up the base image in containerd's image store.
	//
	// GetImage returns the containerd client Image interface, which wraps the
	// metadata image and provides Unpack / RootFS methods.
	img, err := client.GetImage(ctx, baseImage)
	if err != nil {
		if errors.Is(err, cerrdefs.ErrNotFound) {
			return nil, fmt.Errorf("fork: base image %q not found — run 'fastenv build-base' first", baseImage)
		}
		return nil, fmt.Errorf("fork: get base image %q: %w", baseImage, err)
	}

	// Step 2: Ensure image layers are unpacked into the overlayfs snapshotter.
	//
	// Unpack walks the OCI manifest, applies each layer diff to a scratch
	// active snapshot, then commits it as a chain-ID-keyed committed snapshot.
	// Subsequent calls are idempotent: already-present snapshots are skipped.
	//
	// On a warm base image this is a fast metadata check (no I/O).
	if err := img.Unpack(ctx, snapshotterName); err != nil {
		return nil, fmt.Errorf("fork: unpack base image %q into overlayfs: %w", baseImage, err)
	}

	// Step 3: Resolve the top-level committed snapshot key.
	//
	// RootFS returns the OCI chain IDs for each layer. The last chain ID is
	// the committed snapshot key for the top of the parent chain. containerd
	// stores snapshots keyed by their chain ID string (e.g. "sha256:abc…").
	//
	// See OCI image spec §4.6.3 for the chain ID computation:
	//   chainID[0] = diffID[0]
	//   chainID[n] = sha256(chainID[n-1] + " " + diffID[n])
	chainIDs, err := img.RootFS(ctx)
	if err != nil {
		return nil, fmt.Errorf("fork: get RootFS chain IDs for %q: %w", baseImage, err)
	}
	if len(chainIDs) == 0 {
		return nil, fmt.Errorf("fork: base image %q has no layers", baseImage)
	}
	baseSnapshotKey := chainIDs[len(chainIDs)-1].String()

	// Step 4: Check that forkID does not already exist.
	//
	// Stat returns nil error when the snapshot exists. We surface a clear
	// error before attempting Prepare, avoiding the less-readable containerd
	// "already exists" gRPC error.
	sn := client.SnapshotService(snapshotterName)
	if _, err := sn.Stat(ctx, forkID); err == nil {
		return nil, fmt.Errorf("fork: fork %q already exists — choose a different name", forkID)
	}

	// Step 5: Allocate the CoW writable snapshot via overlayfs Prepare.
	//
	// Prepare(forkID, baseSnapshotKey) creates an active snapshot backed by
	// overlayfs. The lower layers are the committed parent chain; the upper dir
	// is a new empty directory unique to this fork. No bytes are copied.
	//
	// Labels carry provenance metadata for observability and GC decisions.
	// fastenv.fork.base: the human-readable base image name.
	// fastenv.fork.created: RFC 3339 creation timestamp.
	//
	// See docs/scout/phase1-findings.md §1 Phase B for the full call sequence.
	_, err = sn.Prepare(ctx, forkID, baseSnapshotKey,
		snapshots.WithLabels(map[string]string{
			"fastenv.fork.base":    baseImage,
			"fastenv.fork.created": time.Now().UTC().Format(time.RFC3339),
		}),
	)
	if err != nil {
		if errors.Is(err, cerrdefs.ErrAlreadyExists) {
			return nil, fmt.Errorf("fork: fork %q already exists — choose a different name", forkID)
		}
		return nil, fmt.Errorf("fork: prepare snapshot %q (parent %q): %w", forkID, baseSnapshotKey, err)
	}

	latency := time.Since(start)
	return &ForkResult{
		ForkID:          forkID,
		BaseImage:       baseImage,
		SnapshotKey:     forkID,
		CreationLatency: latency.Round(time.Microsecond).String(),
	}, nil
}
