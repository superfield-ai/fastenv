// overlayfs_integration_test.go — integration tests for the overlayfs driver.
//
// These tests require a live containerd daemon at the default socket path.
// When containerd is not available the tests skip gracefully (via
// testutil.RequireContainerd) rather than failing. This allows the test suite
// to run in CI environments without containerd.
//
// To run locally against a real containerd daemon:
//
//	sudo go test -v -run TestIntegration ./internal/snapshotter/
//
// # What is tested
//
//   - PrepareBase creates a committed base snapshot in the containerd store.
//   - Fork creates a writable overlayfs snapshot from the base.
//   - Mounts returns non-empty overlayfs mount descriptors.
//   - Discard removes the fork from the snapshot store.
//   - GC runs without error on the default policy.
//
// # Canonical docs
//
//   - docs/implementation-plan.md Phase 2 (integration test strategy)
//   - docs/scout/phase1-findings.md §1 (containerd snapshot API call sequence)
package snapshotter_test

import (
	"context"
	"testing"

	"github.com/superfield-ai/fastenv/internal/client"
	"github.com/superfield-ai/fastenv/internal/snapshotter"
	"github.com/superfield-ai/fastenv/internal/testutil"
)

// requireOverlayfs dials containerd and returns an overlayfs-backed Snapshotter.
// If containerd is not reachable, the test is skipped via t.Skip.
func requireOverlayfs(t *testing.T) snapshotter.Snapshotter {
	t.Helper()
	// Use RequireContainerd to validate containerd is available and skip if not.
	_ = testutil.RequireContainerd(t)

	sn, err := snapshotter.New("overlayfs", client.DefaultSocket, client.DefaultNamespace)
	if err != nil {
		t.Skipf("overlayfs snapshotter unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := sn.Close(); err != nil {
			t.Logf("warning: overlayfs Close: %v", err)
		}
	})
	return sn
}

// TestIntegration_OverlayfsLifecycle exercises the full fork lifecycle against
// a live containerd daemon:
//
//  1. PrepareBase — create a named committed base snapshot
//  2. Fork        — allocate a CoW child of the base
//  3. Mounts      — retrieve overlayfs mount descriptors
//  4. Usage       — read disk usage stats (may be zero for an empty fork)
//  5. Discard     — remove the fork
//  6. GC          — run garbage collection (default policy)
func TestIntegration_OverlayfsLifecycle(t *testing.T) {
	sn := requireOverlayfs(t)
	ctx := context.Background()

	baseKey := "fastenv-test-base"
	forkKey := "fastenv-test-fork"

	// Cleanup base snapshot regardless of test outcome.
	t.Cleanup(func() {
		// Best-effort: base removal may fail if already gone or still referenced.
		sn2, err := snapshotter.New("overlayfs", client.DefaultSocket, client.DefaultNamespace)
		if err != nil {
			return
		}
		defer sn2.Close()
		_ = sn2.Discard(ctx, forkKey) // clean fork first
		_ = sn2.Discard(ctx, baseKey) // then base (active snapshot)
	})

	// Step 1: PrepareBase — creates an empty committed base snapshot.
	t.Log("PrepareBase...")
	if err := sn.PrepareBase(ctx, "test-image-ref", baseKey); err != nil {
		t.Fatalf("PrepareBase: %v", err)
	}

	// Step 2: PrepareBase is idempotent — second call should not error.
	t.Log("PrepareBase (idempotency)...")
	if err := sn.PrepareBase(ctx, "test-image-ref", baseKey); err != nil {
		t.Fatalf("PrepareBase idempotency: %v", err)
	}

	// Step 3: Fork — allocate a CoW writable snapshot from the base.
	t.Log("Fork...")
	if err := sn.Fork(ctx, baseKey, forkKey); err != nil {
		t.Fatalf("Fork: %v", err)
	}

	// Step 4: Mounts — should return overlayfs mount descriptors.
	t.Log("Mounts...")
	mounts, err := sn.Mounts(ctx, forkKey)
	if err != nil {
		t.Fatalf("Mounts: %v", err)
	}
	if len(mounts) == 0 {
		t.Error("expected at least one mount descriptor for an overlayfs fork")
	}
	t.Logf("mounts: %+v", mounts)

	// Step 5: Usage — disk usage for a fresh (empty) fork is expected to be
	// near-zero but the call must succeed.
	t.Log("Usage...")
	u, err := sn.Usage(ctx, forkKey)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	t.Logf("usage: %+v", u)

	// Step 6: Discard — remove the fork.
	t.Log("Discard...")
	if err := sn.Discard(ctx, forkKey); err != nil {
		t.Fatalf("Discard: %v", err)
	}

	// Step 7: GC — should complete without error on default policy.
	t.Log("GC...")
	if err := sn.GC(ctx, snapshotter.GCPolicyDefault); err != nil {
		t.Fatalf("GC: %v", err)
	}
}
