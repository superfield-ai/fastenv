// Package testutil provides helpers for integration tests that require a
// live containerd daemon.
//
// Tests that depend on containerd must call RequireContainerd at the start.
// When a containerd daemon is not reachable at the expected socket, the test
// is skipped with an informative message rather than failing. This allows the
// test suite to run in CI environments where containerd may not be available
// without causing spurious failures.
//
// Usage:
//
//	func TestFork(t *testing.T) {
//	    client := testutil.RequireContainerd(t)
//	    defer client.Close()
//	    // ... test using client ...
//	}
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 1 (integration test harness skeleton)
package testutil

import (
	"testing"

	"github.com/superfield-ai/fastenv/internal/client"
)

// RequireContainerd connects to the containerd daemon at the default socket
// path and returns a client for use in integration tests. If the daemon is
// not reachable, the test is skipped via t.Skip — it is not failed.
//
// The test's cleanup function is registered to close the client automatically
// at test teardown.
func RequireContainerd(t *testing.T) *client.Client {
	t.Helper()

	c, err := client.New(client.DefaultSocket, client.DefaultNamespace)
	if err != nil {
		t.Skipf("containerd not available at %s: %v", client.DefaultSocket, err)
		return nil
	}

	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Logf("warning: failed to close containerd client: %v", err)
		}
	})

	return c
}
