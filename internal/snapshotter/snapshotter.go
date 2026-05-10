// Package snapshotter defines the pluggable abstraction that fastenv places
// over the containerd snapshot API. All snapshot operations in fastenv flow
// through this interface so that the underlying snapshot driver can be swapped
// at runtime via the --snapshotter flag.
//
// # Design rationale
//
// containerd exposes its own Snapshotter interface
// (github.com/containerd/containerd/v2/core/snapshots), but it is tied to
// containerd's internal mount types and storage machinery. fastenv wraps that
// interface with a higher-level, domain-oriented contract that:
//
//   - hides the distinction between "active" and "committed" snapshots from
//     callers that only care about fork/discard semantics.
//   - introduces domain concepts: PrepareBase (ingest an OCI image as an
//     immutable base), Fork (allocate a CoW child), Discard (release a fork).
//   - keeps the GC policy opaque so future phases can swap overlayfs for
//     stargz/nydus without touching call sites.
//
// # Canonical docs
//
//   - docs/architecture.md §2 (containerd as snapshot manager)
//   - docs/implementation-plan.md Phase 2 (snapshotter interface, fork)
//   - docs/scout/phase1-findings.md §1 (containerd snapshot API call sequence)
//
// # Registered drivers
//
// Drivers are registered in init() functions in their own files:
//
//   - overlayfs (default) — overlayfs.go
//   - stargz stub           — stubs.go
//   - nydus stub            — stubs.go
package snapshotter

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
)

// ErrNotImplemented is returned by stub drivers (stargz, nydus) that have
// been registered as future extension points but are not yet functional.
// Callers should treat this error as a signal to fall back to the default
// driver or to surface a clear error to the user.
var ErrNotImplemented = errors.New("snapshotter: not implemented")

// ErrUnknownDriver is returned by New when the requested driver name does not
// match any registered driver.
var ErrUnknownDriver = errors.New("snapshotter: unknown driver")

// GCPolicy controls which snapshots are eligible for garbage collection.
//
// The zero value (GCPolicyDefault) retains all snapshots that are reachable
// from a gc.root label. Unreferenced snapshots are removed.
type GCPolicy int

const (
	// GCPolicyDefault removes only unreferenced (unlabelled) snapshots.
	// This matches containerd's built-in GC behaviour.
	GCPolicyDefault GCPolicy = iota
	// GCPolicyAggressive removes all non-root snapshots, including those
	// with active children. Reserved for future phases.
	GCPolicyAggressive
)

// Usage holds disk-resource statistics for a single snapshot.
//
// Fields match containerd's snapshots.Usage so callers can convert without
// allocation.
type Usage = snapshots.Usage

// Mount describes a single mount point that must be applied to access a
// snapshot's filesystem. It is a direct alias of the containerd mount type so
// callers can pass values to the standard mount helpers without conversion.
type Mount = mount.Mount

// Snapshotter is the domain-level interface that all snapshot drivers must
// satisfy. It wraps the low-level containerd snapshot API with operations
// that map directly onto fastenv's workspace lifecycle:
//
//  1. PrepareBase — ingest a named image as an immutable base snapshot.
//  2. Fork        — allocate a new CoW writable snapshot from a base.
//  3. Mounts      — return the mount descriptors for a fork so a runtime can
//     execute inside it.
//  4. Usage       — return disk usage for a fork (excluding its parent).
//  5. Discard     — release and delete a fork.
//  6. GC          — garbage-collect unreferenced snapshots per the given
//     policy.
//
// Implementations must be safe for concurrent use.
//
// Canonical docs:
//   - docs/architecture.md §2 (snapshot lifecycle)
//   - docs/implementation-plan.md Phase 2 (snapshotter interface)
type Snapshotter interface {
	// PrepareBase ingests the image identified by imageRef into the snapshot
	// store as an immutable base snapshot. The baseKey is the caller-assigned
	// name for this base; it must be unique within the store.
	//
	// If the base already exists the implementation should return nil (idempotent).
	PrepareBase(ctx context.Context, imageRef, baseKey string) error

	// Fork creates a new writable snapshot identified by forkKey that uses
	// baseKey as its immutable parent (copy-on-write). The fork is ready for
	// exec immediately; no data is copied from the base.
	//
	// Returns ErrNotImplemented for stub drivers.
	Fork(ctx context.Context, baseKey, forkKey string) error

	// Mounts returns the set of mount descriptors required to access the
	// writable layer of forkKey. Callers pass these to the container runtime
	// or to mount(8) to gain filesystem access.
	Mounts(ctx context.Context, forkKey string) ([]Mount, error)

	// Usage reports disk resources consumed by forkKey, excluding its parent
	// chain. Values are in bytes (Size) and inodes (Inodes).
	Usage(ctx context.Context, forkKey string) (Usage, error)

	// Discard removes the writable snapshot identified by forkKey from the
	// snapshot store. Any in-progress mounts will be invalidated.
	// The base snapshot is not affected.
	Discard(ctx context.Context, forkKey string) error

	// GC triggers garbage collection according to policy. Unreferenced
	// snapshots that do not carry the containerd.io/gc.root label are removed.
	GC(ctx context.Context, policy GCPolicy) error

	// Close releases any resources held by the driver (e.g. gRPC connections).
	// Safe to call multiple times.
	Close() error
}

// ConstructorFunc is the factory signature that each driver registers.
// socketPath is the containerd gRPC socket; namespace is the containerd
// namespace to operate in.
type ConstructorFunc func(socketPath, namespace string) (Snapshotter, error)

var (
	mu       sync.RWMutex
	registry = map[string]ConstructorFunc{}
)

// Register records a driver constructor under name. It panics if the same
// name is registered twice, which catches typos at init time.
//
// Driver packages call Register in their init() functions so that the main
// package only needs to blank-import them.
func Register(name string, fn ConstructorFunc) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := registry[name]; ok {
		panic(fmt.Sprintf("snapshotter: driver %q already registered", name))
	}
	registry[name] = fn
}

// New looks up the driver registered under name and calls its constructor.
// It returns ErrUnknownDriver (wrapped) when name is not found.
func New(name, socketPath, namespace string) (Snapshotter, error) {
	mu.RLock()
	fn, ok := registry[name]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownDriver, name)
	}
	return fn(socketPath, namespace)
}

// Drivers returns the sorted list of registered driver names. Useful for
// error messages and help text.
func Drivers() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	return names
}
