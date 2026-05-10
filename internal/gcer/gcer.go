// Package gcer implements fork garbage collection: TTL-based and LRU-based
// eviction of idle fork snapshots, plus an explicit on-demand sweep.
//
// # Design
//
//  1. Walk all active snapshots in the configured namespace.
//  2. For each active snapshot that carries a "fastenv.fork.created" label
//     (i.e. a fork created by `fastenv fork`), apply the TTL and LRU policies:
//     - TTL: if the fork's creation timestamp is older than gcTTL, mark for
//       eviction with reason "ttl".
//     - LRU: if total writable-layer disk usage exceeds gcMaxDisk, evict the
//       least-recently-used forks (oldest first) until usage is below the
//       threshold, marking each with reason "lru".
//  3. Skip forks that are currently executing (reserved for future: a running
//     task label could be checked; for now we rely on containerd returning an
//     error on Remove if the snapshot is in use).
//  4. Emit a structured JSON log line for each evicted fork.
//  5. Return a GCResult summarising forks evicted and bytes reclaimed.
//
// # Lazy GC
//
// Lazy GC is triggered on every `fastenv fork` and `fastenv discard` call
// by calling RunGC with the same options supplied to the invoking command.
// This ensures expired forks are cleaned up opportunistically without a
// background daemon.
//
// # Canonical docs
//
//   - docs/architecture.md §5 OD-3 (fork GC scheduling)
//   - docs/implementation-plan.md Phase 6 (GC)
package gcer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

const (
	// dialTimeout is the maximum time to wait for a containerd gRPC connection.
	dialTimeout = 10 * time.Second

	// snapshotterName is the containerd snapshotter plugin used for all fork
	// operations.
	snapshotterName = "overlayfs"

	// forkCreatedLabel is the snapshot label written at fork creation time.
	// Value is an RFC 3339 UTC timestamp.
	forkCreatedLabel = "fastenv.fork.created"

	// forkBaseLabel is the snapshot label carrying the base image name.
	forkBaseLabel = "fastenv.fork.base"

	// DefaultTTL is the default fork TTL: forks older than this are eligible
	// for TTL eviction.
	DefaultTTL = 24 * time.Hour

	// DefaultMaxDisk is the default total writable-layer disk budget (10 GiB).
	// When total usage exceeds this, LRU eviction kicks in.
	DefaultMaxDisk = 10 * 1024 * 1024 * 1024 // 10 GiB
)

// Options controls RunGC behaviour.
type Options struct {
	// SocketPath is the containerd gRPC Unix socket path.
	// Defaults to /run/containerd/containerd.sock if empty.
	SocketPath string
	// Namespace is the containerd namespace to operate in.
	// Defaults to "fastenv" if empty.
	Namespace string
	// TTL is the maximum age of a fork before it is eligible for TTL eviction.
	// Zero means use DefaultTTL.
	TTL time.Duration
	// MaxDisk is the total writable-layer disk budget in bytes.
	// When total usage exceeds this, LRU eviction starts.
	// Zero means use DefaultMaxDisk.
	MaxDisk int64
	// Out is the writer for structured JSON eviction log lines.
	// Defaults to io.Discard if nil.
	Out io.Writer
	// Now is a hook for testing to override the current time.
	// Defaults to time.Now() if nil.
	Now func() time.Time
}

// EvictionRecord is the structured JSON log line emitted for each evicted fork.
type EvictionRecord struct {
	// ForkID is the snapshot key of the evicted fork.
	ForkID string `json:"fork_id"`
	// Reason is the eviction trigger: "ttl", "lru", or "explicit".
	Reason string `json:"reason"`
	// BytesReclaimed is the number of writable-layer bytes freed.
	BytesReclaimed int64 `json:"bytes_reclaimed"`
}

// GCResult summarises a completed GC sweep.
type GCResult struct {
	// ForksEvicted is the number of fork snapshots that were removed.
	ForksEvicted int `json:"forks_evicted"`
	// BytesReclaimed is the total writable-layer bytes freed across all evictions.
	BytesReclaimed int64 `json:"bytes_reclaimed"`
}

// forkEntry is an internal record built from a single snapshot Walk entry.
type forkEntry struct {
	name      string
	createdAt time.Time
	sizeBytes int64
}

// RunGC performs a GC sweep against all fork snapshots in the configured
// namespace. It applies TTL and LRU eviction policies, emits a structured JSON
// log line per eviction, and returns an aggregate GCResult.
//
// RunGC is safe to call concurrently: containerd's snapshot store is
// serialised internally. Errors removing individual forks (e.g. because a
// fork is in use) are logged to opts.Out but do not abort the sweep.
func RunGC(ctx context.Context, opts Options) (*GCResult, error) {
	if opts.SocketPath == "" {
		opts.SocketPath = "/run/containerd/containerd.sock"
	}
	if opts.Namespace == "" {
		opts.Namespace = "fastenv"
	}
	if opts.TTL <= 0 {
		opts.TTL = DefaultTTL
	}
	if opts.MaxDisk <= 0 {
		opts.MaxDisk = DefaultMaxDisk
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	client, err := containerd.New(opts.SocketPath,
		containerd.WithDefaultNamespace(opts.Namespace),
		containerd.WithTimeout(dialTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("gc: dial containerd at %s: %w", opts.SocketPath, err)
	}
	defer client.Close()

	ctx = namespaces.WithNamespace(ctx, opts.Namespace)
	sn := client.SnapshotService(snapshotterName)

	now := opts.Now()

	// Phase 1: Walk all active snapshots and collect fastenv fork entries.
	var forks []forkEntry
	if err := sn.Walk(ctx, func(_ context.Context, info snapshots.Info) error {
		if info.Kind != snapshots.KindActive {
			return nil
		}
		createdRaw, ok := info.Labels[forkCreatedLabel]
		if !ok {
			// Not a fastenv fork snapshot; skip.
			return nil
		}
		createdAt, parseErr := time.Parse(time.RFC3339, createdRaw)
		if parseErr != nil {
			// Malformed label: skip silently.
			return nil
		}

		// Measure writable-layer disk usage.
		usage, usageErr := sn.Usage(ctx, info.Name)
		var sizeBytes int64
		if usageErr == nil {
			sizeBytes = usage.Size
		}

		forks = append(forks, forkEntry{
			name:      info.Name,
			createdAt: createdAt,
			sizeBytes: sizeBytes,
		})
		return nil
	}); err != nil {
		return nil, fmt.Errorf("gc: walk snapshots: %w", err)
	}

	// Sort forks oldest-first for deterministic LRU ordering.
	sort.Slice(forks, func(i, j int) bool {
		return forks[i].createdAt.Before(forks[j].createdAt)
	})

	// Phase 2: TTL eviction — collect forks older than opts.TTL.
	evictSet := map[string]string{} // name → reason
	for _, f := range forks {
		if now.Sub(f.createdAt) > opts.TTL {
			evictSet[f.name] = "ttl"
		}
	}

	// Phase 3: LRU eviction — if total disk usage exceeds opts.MaxDisk,
	// evict oldest forks (not already TTL-evicted) until under budget.
	var totalDisk int64
	for _, f := range forks {
		totalDisk += f.sizeBytes
	}
	if totalDisk > opts.MaxDisk {
		for _, f := range forks {
			if totalDisk <= opts.MaxDisk {
				break
			}
			if _, alreadyEvicted := evictSet[f.name]; alreadyEvicted {
				// Already marked for TTL; deduct from running total.
				totalDisk -= f.sizeBytes
				continue
			}
			evictSet[f.name] = "lru"
			totalDisk -= f.sizeBytes
		}
	}

	// Phase 4: Execute evictions and emit structured log lines.
	enc := json.NewEncoder(opts.Out)
	enc.SetEscapeHTML(false)

	result := &GCResult{}
	for _, f := range forks {
		reason, shouldEvict := evictSet[f.name]
		if !shouldEvict {
			continue
		}

		if removeErr := sn.Remove(ctx, f.name); removeErr != nil {
			// Fork may be in use (running task). Skip; do not count as evicted.
			// A structured warning is emitted so operators can observe it.
			_ = enc.Encode(map[string]string{
				"fork_id": f.name,
				"warning": fmt.Sprintf("gc: skip eviction (remove failed): %s", removeErr.Error()),
			})
			continue
		}

		rec := EvictionRecord{
			ForkID:         f.name,
			Reason:         reason,
			BytesReclaimed: f.sizeBytes,
		}
		_ = enc.Encode(rec)

		result.ForksEvicted++
		result.BytesReclaimed += f.sizeBytes
	}

	return result, nil
}
