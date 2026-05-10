// stubs.go — placeholder Snapshotter drivers for future snapshot backends.
//
// stargz and nydus are registered here so the --snapshotter flag can validate
// driver names at startup and surface a clear "not implemented" error rather
// than an obscure panic. These stubs also serve as extension points: future
// phases replace each stub's factory function with a real implementation.
//
// # stargz
//
// Stargz (Seekable tar.gz) is a lazy-pulling OCI image format developed by
// containerd. Layers are fetched on-demand rather than pulled in full before
// the container starts, which can dramatically reduce startup latency for
// large images. Integration requires the estargz containerd snapshotter plugin.
//
// # nydus
//
// Nydus is a container image acceleration framework from Dragonfly. It uses a
// RAFS (Registry Acceleration File System) format and a FUSE daemon (nydusd)
// to serve content from remote registries with data-deduplication and lazy
// pulling. Integration requires a running nydusd and the nydus-snapshotter
// containerd plugin.
//
// # Canonical docs
//
//   - docs/architecture.md §2 (pluggable snapshotter)
//   - docs/implementation-plan.md Phase 4 (stargz/nydus)
//   - docs/scout/phase1-findings.md §6 (alternative snapshotter risks)
package snapshotter

import (
	"context"
	"fmt"
)

func init() {
	Register("stargz", newStub("stargz"))
	Register("nydus", newStub("nydus"))
}

// newStub returns a ConstructorFunc that always produces a stubSnapshotter
// labelled with the given driver name.
func newStub(name string) ConstructorFunc {
	return func(_, _ string) (Snapshotter, error) {
		return &stubSnapshotter{name: name}, nil
	}
}

// stubSnapshotter satisfies the Snapshotter interface but returns
// ErrNotImplemented for every operation. It is used as a registration point
// for future drivers.
type stubSnapshotter struct {
	name string
}

func (s *stubSnapshotter) notImpl(op string) error {
	return fmt.Errorf("snapshotter %q %s: %w", s.name, op, ErrNotImplemented)
}

func (s *stubSnapshotter) PrepareBase(_ context.Context, _, _ string) error {
	return s.notImpl("PrepareBase")
}

func (s *stubSnapshotter) Fork(_ context.Context, _, _ string) error {
	return s.notImpl("Fork")
}

func (s *stubSnapshotter) Mounts(_ context.Context, _ string) ([]Mount, error) {
	return nil, s.notImpl("Mounts")
}

func (s *stubSnapshotter) Usage(_ context.Context, _ string) (Usage, error) {
	return Usage{}, s.notImpl("Usage")
}

func (s *stubSnapshotter) Discard(_ context.Context, _ string) error {
	return s.notImpl("Discard")
}

func (s *stubSnapshotter) GC(_ context.Context, _ GCPolicy) error {
	return s.notImpl("GC")
}

func (s *stubSnapshotter) Close() error { return nil }
