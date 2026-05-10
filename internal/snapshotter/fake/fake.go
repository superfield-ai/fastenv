// Package fake provides an in-memory Snapshotter implementation for unit
// testing code that depends on the snapshotter.Snapshotter interface.
//
// The fake does not touch the filesystem or require a containerd daemon. It
// records operations in memory and exposes helper methods for inspecting state
// in tests.
//
// Usage:
//
//	func TestMyThing(t *testing.T) {
//	    sn := fake.New()
//	    // inject sn wherever a snapshotter.Snapshotter is expected
//	    if err := sn.PrepareBase(ctx, "ubuntu:22.04", "ubuntu-base"); err != nil {
//	        t.Fatal(err)
//	    }
//	    // assert via sn.Bases(), sn.Forks(), sn.DiscardedForks()
//	}
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 2 (unit test strategy)
//   - docs/scout/phase1-findings.md §1 (snapshot lifecycle)
package fake

import (
	"context"
	"fmt"
	"sync"

	"github.com/superfield-ai/fastenv/internal/snapshotter"
)

// Snapshotter is an in-memory implementation of snapshotter.Snapshotter for
// use in unit tests. All operations are goroutine-safe.
type Snapshotter struct {
	mu        sync.RWMutex
	bases     map[string]string // baseKey → imageRef
	forks     map[string]string // forkKey → baseKey
	discarded map[string]bool   // forkKey → true if Discard was called
	gcCount   int               // number of GC calls
	closed    bool
	forceErr  error // when non-nil every method returns this error
}

// New returns a zeroed fake Snapshotter ready to use.
func New() *Snapshotter {
	return &Snapshotter{
		bases:     make(map[string]string),
		forks:     make(map[string]string),
		discarded: make(map[string]bool),
	}
}

// ForceError makes every subsequent method call return err. Pass nil to clear.
// Useful for testing error-handling paths.
func (s *Snapshotter) ForceError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forceErr = err
}

func (s *Snapshotter) checkError() error {
	if s.forceErr != nil {
		return s.forceErr
	}
	return nil
}

// PrepareBase records the (imageRef, baseKey) pair. Idempotent: if baseKey
// already exists the call is a no-op.
func (s *Snapshotter) PrepareBase(_ context.Context, imageRef, baseKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkError(); err != nil {
		return fmt.Errorf("fake PrepareBase: %w", err)
	}
	if _, ok := s.bases[baseKey]; !ok {
		s.bases[baseKey] = imageRef
	}
	return nil
}

// Fork records a new fork of baseKey. Returns an error if baseKey has not been
// prepared or if forkKey already exists.
func (s *Snapshotter) Fork(_ context.Context, baseKey, forkKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkError(); err != nil {
		return fmt.Errorf("fake Fork: %w", err)
	}
	if _, ok := s.bases[baseKey]; !ok {
		return fmt.Errorf("fake Fork: base %q not found", baseKey)
	}
	if _, ok := s.forks[forkKey]; ok {
		return fmt.Errorf("fake Fork: fork %q already exists", forkKey)
	}
	s.forks[forkKey] = baseKey
	return nil
}

// Mounts returns a non-nil but empty slice. Real overlayfs mounts are not
// meaningful in-process.
func (s *Snapshotter) Mounts(_ context.Context, forkKey string) ([]snapshotter.Mount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkError(); err != nil {
		return nil, fmt.Errorf("fake Mounts: %w", err)
	}
	if _, ok := s.forks[forkKey]; !ok {
		return nil, fmt.Errorf("fake Mounts: fork %q not found", forkKey)
	}
	// Return an empty slice: callers that inspect mount descriptors in unit
	// tests should use an integration test with a real containerd daemon.
	return []snapshotter.Mount{}, nil
}

// Usage returns a zeroed Usage struct. Callers testing disk accounting should
// use integration tests.
func (s *Snapshotter) Usage(_ context.Context, forkKey string) (snapshotter.Usage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkError(); err != nil {
		return snapshotter.Usage{}, fmt.Errorf("fake Usage: %w", err)
	}
	if _, ok := s.forks[forkKey]; !ok {
		return snapshotter.Usage{}, fmt.Errorf("fake Usage: fork %q not found", forkKey)
	}
	return snapshotter.Usage{}, nil
}

// Discard marks forkKey as discarded and removes it from the active forks map.
func (s *Snapshotter) Discard(_ context.Context, forkKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkError(); err != nil {
		return fmt.Errorf("fake Discard: %w", err)
	}
	if _, ok := s.forks[forkKey]; !ok {
		return fmt.Errorf("fake Discard: fork %q not found", forkKey)
	}
	delete(s.forks, forkKey)
	s.discarded[forkKey] = true
	return nil
}

// GC increments the GC call counter. Aggressive policy is not simulated.
func (s *Snapshotter) GC(_ context.Context, policy snapshotter.GCPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkError(); err != nil {
		return fmt.Errorf("fake GC: %w", err)
	}
	s.gcCount++
	return nil
}

// Close marks the snapshotter as closed. Subsequent calls still succeed (the
// fake does not enforce post-close invariants).
func (s *Snapshotter) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// --- Inspection helpers for test assertions ---

// Bases returns a snapshot of the base-snapshot registry (baseKey → imageRef).
func (s *Snapshotter) Bases() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.bases))
	for k, v := range s.bases {
		out[k] = v
	}
	return out
}

// Forks returns a snapshot of the active-fork registry (forkKey → baseKey).
func (s *Snapshotter) Forks() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.forks))
	for k, v := range s.forks {
		out[k] = v
	}
	return out
}

// DiscardedForks returns the set of fork keys that have been discarded.
func (s *Snapshotter) DiscardedForks() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.discarded))
	for k := range s.discarded {
		out = append(out, k)
	}
	return out
}

// GCCount returns the number of times GC has been called.
func (s *Snapshotter) GCCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.gcCount
}

// IsClosed returns true if Close has been called.
func (s *Snapshotter) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// Compile-time assertion: fake.Snapshotter must satisfy snapshotter.Snapshotter.
var _ snapshotter.Snapshotter = (*Snapshotter)(nil)

// ErrNotImplemented re-exports the package-level sentinel for tests that need
// to assert on it without importing the parent package.
var ErrNotImplemented = snapshotter.ErrNotImplemented

// ErrUnknownDriver re-exports the package-level sentinel.
var ErrUnknownDriver = snapshotter.ErrUnknownDriver

// HasBase returns true if baseKey has been prepared.
func (s *Snapshotter) HasBase(baseKey string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.bases[baseKey]
	return ok
}

// HasFork returns true if forkKey is currently active (not discarded).
func (s *Snapshotter) HasFork(forkKey string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.forks[forkKey]
	return ok
}
