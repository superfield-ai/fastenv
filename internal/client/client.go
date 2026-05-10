// Package client provides a thin wrapper around the containerd v2 Go client.
//
// It handles connection lifecycle (dial, close) and injects the fastenv
// containerd namespace into every context. All higher-level operations
// (snapshot management, image management, task lifecycle) use this client
// as their entry point.
//
// Integration notes from the Phase 1 scout (docs/scout/phase1-findings.md):
//   - Socket path defaults to /run/containerd/containerd.sock but must be
//     configurable via flag/env for non-standard installations.
//   - All operations must use a dedicated containerd namespace (default:
//     "fastenv") to avoid collisions with Docker/CRI containers.
//   - The correct v2 import path is github.com/containerd/containerd/v2/client.
//
// Canonical docs:
//   - docs/architecture.md §2 (containerd as snapshot manager)
//   - docs/implementation-plan.md Phase 1 (scaffold deliverables)
package client

import (
	"context"
	"fmt"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

const (
	// DefaultSocket is the standard containerd Unix domain socket path.
	DefaultSocket = "/run/containerd/containerd.sock"

	// DefaultNamespace is the containerd namespace fastenv uses for all
	// snapshots, images, and containers. Using a dedicated namespace avoids
	// collisions with Docker or Kubernetes CRI resources on the same host.
	// See docs/scout/phase1-findings.md §7.
	DefaultNamespace = "fastenv"

	// dialTimeout is the maximum time to wait for a containerd connection.
	dialTimeout = 10 * time.Second
)

// Client wraps a containerd client with fastenv-specific context injection.
type Client struct {
	inner     *containerd.Client
	namespace string
}

// New dials the containerd gRPC socket at socketPath and returns a Client.
// The namespace parameter controls which containerd namespace all operations
// are scoped to.
//
// The caller is responsible for closing the client via Close when done.
func New(socketPath, namespace string) (*Client, error) {
	if socketPath == "" {
		socketPath = DefaultSocket
	}
	if namespace == "" {
		namespace = DefaultNamespace
	}

	inner, err := containerd.New(socketPath,
		containerd.WithDefaultNamespace(namespace),
		containerd.WithTimeout(dialTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("dial containerd at %s: %w", socketPath, err)
	}

	return &Client{inner: inner, namespace: namespace}, nil
}

// WithNamespace returns a context annotated with the client's containerd
// namespace. All containerd API calls must use a context returned by this
// method (or one derived from it) to ensure operations land in the correct
// namespace.
func (c *Client) WithNamespace(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, c.namespace)
}

// Inner returns the underlying containerd.Client for operations not yet
// wrapped by this package. Callers should prefer the higher-level methods
// on Client and resort to Inner only when necessary.
func (c *Client) Inner() *containerd.Client {
	return c.inner
}

// Close releases the containerd gRPC connection. Safe to call multiple times.
func (c *Client) Close() error {
	if c.inner == nil {
		return nil
	}
	return c.inner.Close()
}
