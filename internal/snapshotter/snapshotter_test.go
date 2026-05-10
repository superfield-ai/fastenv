// Package snapshotter_test tests the Snapshotter interface contract using the
// fake in-memory driver. These tests do not require a containerd daemon.
//
// The test suite exercises every method in the Snapshotter interface to verify
// that any conforming implementation (overlayfs, stargz stub, nydus stub) can
// be swapped in without breaking callers.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 2 (unit test strategy)
package snapshotter_test

import (
	"context"
	"errors"
	"testing"

	"github.com/superfield-ai/fastenv/internal/snapshotter"
	"github.com/superfield-ai/fastenv/internal/snapshotter/fake"
)

func TestFakeSnapshotter_PrepareBase(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()

	if err := sn.PrepareBase(ctx, "ubuntu:22.04", "ubuntu-base"); err != nil {
		t.Fatalf("PrepareBase: %v", err)
	}
	if !sn.HasBase("ubuntu-base") {
		t.Error("expected base 'ubuntu-base' to be registered")
	}

	// Idempotency: second call should not return an error.
	if err := sn.PrepareBase(ctx, "ubuntu:22.04", "ubuntu-base"); err != nil {
		t.Fatalf("PrepareBase idempotency: %v", err)
	}
}

func TestFakeSnapshotter_Fork(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()

	if err := sn.PrepareBase(ctx, "ubuntu:22.04", "base"); err != nil {
		t.Fatal(err)
	}
	if err := sn.Fork(ctx, "base", "fork-1"); err != nil {
		t.Fatalf("Fork: %v", err)
	}
	if !sn.HasFork("fork-1") {
		t.Error("expected fork 'fork-1' to be active")
	}
	forks := sn.Forks()
	if forks["fork-1"] != "base" {
		t.Errorf("fork parent: got %q, want %q", forks["fork-1"], "base")
	}
}

func TestFakeSnapshotter_Fork_UnknownBase(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()

	err := sn.Fork(ctx, "nonexistent-base", "fork-x")
	if err == nil {
		t.Fatal("expected error for unknown base, got nil")
	}
}

func TestFakeSnapshotter_Fork_DuplicateKey(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()
	_ = sn.PrepareBase(ctx, "img", "base")
	_ = sn.Fork(ctx, "base", "fork-a")

	err := sn.Fork(ctx, "base", "fork-a")
	if err == nil {
		t.Fatal("expected error for duplicate fork key, got nil")
	}
}

func TestFakeSnapshotter_Mounts(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()
	_ = sn.PrepareBase(ctx, "img", "base")
	_ = sn.Fork(ctx, "base", "fork-1")

	mounts, err := sn.Mounts(ctx, "fork-1")
	if err != nil {
		t.Fatalf("Mounts: %v", err)
	}
	// The fake returns an empty (non-nil) slice.
	if mounts == nil {
		t.Error("expected non-nil mounts slice")
	}
}

func TestFakeSnapshotter_Mounts_UnknownFork(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()

	_, err := sn.Mounts(ctx, "missing-fork")
	if err == nil {
		t.Fatal("expected error for unknown fork, got nil")
	}
}

func TestFakeSnapshotter_Usage(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()
	_ = sn.PrepareBase(ctx, "img", "base")
	_ = sn.Fork(ctx, "base", "fork-1")

	u, err := sn.Usage(ctx, "fork-1")
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	// Fake always returns zero usage.
	if u.Size != 0 || u.Inodes != 0 {
		t.Errorf("expected zero usage, got %+v", u)
	}
}

func TestFakeSnapshotter_Discard(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()
	_ = sn.PrepareBase(ctx, "img", "base")
	_ = sn.Fork(ctx, "base", "fork-1")

	if err := sn.Discard(ctx, "fork-1"); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if sn.HasFork("fork-1") {
		t.Error("fork-1 should no longer be active after Discard")
	}
	discarded := sn.DiscardedForks()
	found := false
	for _, k := range discarded {
		if k == "fork-1" {
			found = true
		}
	}
	if !found {
		t.Error("fork-1 should appear in DiscardedForks")
	}
}

func TestFakeSnapshotter_Discard_UnknownFork(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()

	err := sn.Discard(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error when discarding unknown fork, got nil")
	}
}

func TestFakeSnapshotter_GC(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()

	if err := sn.GC(ctx, snapshotter.GCPolicyDefault); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if sn.GCCount() != 1 {
		t.Errorf("GCCount: got %d, want 1", sn.GCCount())
	}
}

func TestFakeSnapshotter_Close(t *testing.T) {
	sn := fake.New()
	if err := sn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !sn.IsClosed() {
		t.Error("expected IsClosed to return true after Close")
	}
}

func TestFakeSnapshotter_ForceError(t *testing.T) {
	ctx := context.Background()
	sn := fake.New()
	sentinel := errors.New("injected error")
	sn.ForceError(sentinel)

	err := sn.PrepareBase(ctx, "img", "base")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got: %v", err)
	}

	// Clear the force error and ensure operations succeed again.
	sn.ForceError(nil)
	if err := sn.PrepareBase(ctx, "img", "base"); err != nil {
		t.Fatalf("after clearing error: %v", err)
	}
}

// TestRegistry verifies that the overlayfs, stargz, and nydus drivers are
// registered and that an unknown name returns a wrapped ErrUnknownDriver.
func TestRegistry(t *testing.T) {
	// Ensure the drivers are loaded by importing the snapshotter package which
	// triggers init() registrations in overlayfs.go and stubs.go.
	drivers := snapshotter.Drivers()
	want := map[string]bool{"overlayfs": true, "stargz": true, "nydus": true}
	for _, d := range drivers {
		delete(want, d)
	}
	if len(want) > 0 {
		t.Errorf("missing registered drivers: %v", want)
	}

	// Unknown driver should return ErrUnknownDriver.
	_, err := snapshotter.New("bogus-driver", "/run/containerd/containerd.sock", "fastenv")
	if err == nil {
		t.Fatal("expected error for unknown driver, got nil")
	}
	if !errors.Is(err, snapshotter.ErrUnknownDriver) {
		t.Errorf("expected ErrUnknownDriver, got: %v", err)
	}
}

// TestStubDrivers verifies that the stargz and nydus drivers return
// ErrNotImplemented for all operations.
func TestStubDrivers(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"stargz", "nydus"} {
		name := name
		t.Run(name, func(t *testing.T) {
			// Stubs don't need a real socket — they return ErrNotImplemented
			// without touching the filesystem.
			sn, err := snapshotter.New(name, "", "fastenv")
			if err != nil {
				t.Fatalf("New(%q): %v", name, err)
			}
			defer sn.Close()

			assertNotImpl := func(err error) {
				t.Helper()
				if err == nil {
					t.Fatal("expected ErrNotImplemented, got nil")
				}
				if !errors.Is(err, snapshotter.ErrNotImplemented) {
					t.Errorf("expected ErrNotImplemented, got: %v", err)
				}
			}

			assertNotImpl(sn.PrepareBase(ctx, "img", "base"))
			assertNotImpl(sn.Fork(ctx, "base", "fork"))
			_, err = sn.Mounts(ctx, "fork")
			assertNotImpl(err)
			_, err = sn.Usage(ctx, "fork")
			assertNotImpl(err)
			assertNotImpl(sn.Discard(ctx, "fork"))
			assertNotImpl(sn.GC(ctx, snapshotter.GCPolicyDefault))
		})
	}
}
