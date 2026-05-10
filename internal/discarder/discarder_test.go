// Package discarder_test exercises the discard lifecycle using the fake
// snapshotter. These tests do not require a live containerd daemon.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 2 (discard, test plan)
//   - docs/scout/phase1-findings.md §1 Phase C (snapshot Remove)
package discarder_test

import (
	"context"
	"testing"

	"github.com/superfield-ai/fastenv/internal/snapshotter/fake"
)

// TestFakeSnapshotter_DiscardHappyPath verifies the core discard contract using
// the in-memory fake: a fork that was Prepared can be Discarded once, and after
// discarding it no longer appears in the active forks map.
func TestFakeSnapshotter_DiscardHappyPath(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()

	// Set up a base and a fork via the fake snapshotter.
	if err := sn.PrepareBase(ctx, "ubuntu:22.04", "ubuntu-base"); err != nil {
		t.Fatalf("PrepareBase: %v", err)
	}
	if err := sn.Fork(ctx, "ubuntu-base", "agent-1"); err != nil {
		t.Fatalf("Fork: %v", err)
	}

	// Verify the fork is active before discard.
	if !sn.HasFork("agent-1") {
		t.Fatal("expected fork agent-1 to exist before Discard")
	}

	// Discard the fork.
	if err := sn.Discard(ctx, "agent-1"); err != nil {
		t.Fatalf("Discard: %v", err)
	}

	// Verify the fork is gone from the active set.
	if sn.HasFork("agent-1") {
		t.Error("expected fork agent-1 to be gone after Discard")
	}

	// Verify it appears in the discarded set.
	discarded := sn.DiscardedForks()
	found := false
	for _, k := range discarded {
		if k == "agent-1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected agent-1 in DiscardedForks, got %v", discarded)
	}
}

// TestFakeSnapshotter_DiscardNonExistentFork verifies that attempting to discard
// a fork that has never been created returns a clear error.
func TestFakeSnapshotter_DiscardNonExistentFork(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()

	err := sn.Discard(ctx, "ghost-fork")
	if err == nil {
		t.Fatal("expected error when discarding non-existent fork, got nil")
	}
}

// TestFakeSnapshotter_BaseUnaffectedAfterDiscard verifies that discarding a
// fork does not remove the base snapshot. Any number of forks can still be
// created from the base after one fork is discarded.
func TestFakeSnapshotter_BaseUnaffectedAfterDiscard(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()

	if err := sn.PrepareBase(ctx, "ubuntu:22.04", "ubuntu-base"); err != nil {
		t.Fatalf("PrepareBase: %v", err)
	}
	if err := sn.Fork(ctx, "ubuntu-base", "agent-1"); err != nil {
		t.Fatalf("Fork agent-1: %v", err)
	}
	if err := sn.Discard(ctx, "agent-1"); err != nil {
		t.Fatalf("Discard agent-1: %v", err)
	}

	// The base must still be present.
	if !sn.HasBase("ubuntu-base") {
		t.Error("base ubuntu-base should still exist after fork discard")
	}

	// A new fork from the same base must succeed.
	if err := sn.Fork(ctx, "ubuntu-base", "agent-2"); err != nil {
		t.Fatalf("Fork agent-2 after discard of agent-1: %v", err)
	}
	if !sn.HasFork("agent-2") {
		t.Error("expected agent-2 to be active after re-fork")
	}
}

// TestFakeSnapshotter_GCAfterDiscard verifies that calling GC after a discard
// increments the GC counter (the fake does not simulate actual storage
// reclamation, but we verify GC is invocable without error).
func TestFakeSnapshotter_GCAfterDiscard(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()

	if err := sn.PrepareBase(ctx, "ubuntu:22.04", "ubuntu-base"); err != nil {
		t.Fatalf("PrepareBase: %v", err)
	}
	if err := sn.Fork(ctx, "ubuntu-base", "agent-1"); err != nil {
		t.Fatalf("Fork: %v", err)
	}
	if err := sn.Discard(ctx, "agent-1"); err != nil {
		t.Fatalf("Discard: %v", err)
	}

	// GC with default policy must succeed.
	if err := sn.GC(ctx, 0 /* GCPolicyDefault */); err != nil {
		t.Fatalf("GC after discard: %v", err)
	}
	if sn.GCCount() != 1 {
		t.Errorf("expected GCCount=1, got %d", sn.GCCount())
	}
}

// TestFakeSnapshotter_MultipleForksDiscard verifies that discarding one fork
// does not affect sibling forks created from the same base.
func TestFakeSnapshotter_MultipleForksDiscard(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()

	if err := sn.PrepareBase(ctx, "ubuntu:22.04", "ubuntu-base"); err != nil {
		t.Fatalf("PrepareBase: %v", err)
	}

	forks := []string{"agent-1", "agent-2", "agent-3"}
	for _, f := range forks {
		if err := sn.Fork(ctx, "ubuntu-base", f); err != nil {
			t.Fatalf("Fork %s: %v", f, err)
		}
	}

	// Discard only agent-1.
	if err := sn.Discard(ctx, "agent-1"); err != nil {
		t.Fatalf("Discard agent-1: %v", err)
	}

	// agent-2 and agent-3 must still be active.
	for _, f := range []string{"agent-2", "agent-3"} {
		if !sn.HasFork(f) {
			t.Errorf("expected %s to remain active after agent-1 discarded", f)
		}
	}
}
