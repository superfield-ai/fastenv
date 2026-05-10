// execer_test.go — unit tests for the execer package.
//
// These tests exercise the OCI spec building logic and network mode validation
// without requiring a live containerd daemon.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 3 (exec)
package execer

import (
	"context"
	"testing"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// TestNetworkModeConstants verifies that the NetworkMode constants have the
// expected string values required by the --network CLI flag.
func TestNetworkModeConstants(t *testing.T) {
	if string(NetworkNone) != "none" {
		t.Errorf("NetworkNone = %q, want %q", NetworkNone, "none")
	}
	if string(NetworkHost) != "host" {
		t.Errorf("NetworkHost = %q, want %q", NetworkHost, "host")
	}
}

// TestBuildSpecOptsNetworkNone verifies that the OCI spec includes a network
// namespace entry when NetworkNone is set, providing loopback-only isolation.
func TestBuildSpecOptsNetworkNone(t *testing.T) {
	sopts := buildSpecOpts([]string{"sh"}, Options{
		WorkDir: "/",
		Network: NetworkNone,
	})

	sp := applySpecOpts(t, sopts)

	if !hasNamespaceType(sp, specs.NetworkNamespace) {
		t.Error("NetworkNone: expected network namespace in OCI spec, but not found")
	}
}

// TestBuildSpecOptsNetworkHost verifies that the OCI spec does NOT include a
// network namespace entry when NetworkHost is set.
func TestBuildSpecOptsNetworkHost(t *testing.T) {
	sopts := buildSpecOpts([]string{"sh"}, Options{
		WorkDir: "/",
		Network: NetworkHost,
	})

	sp := applySpecOpts(t, sopts)

	if hasNamespaceType(sp, specs.NetworkNamespace) {
		t.Error("NetworkHost: unexpected network namespace in OCI spec")
	}
}

// TestBuildSpecOptsAlwaysHasMountAndPIDNamespaces verifies that both mount and
// PID namespaces are always present regardless of the network mode.
func TestBuildSpecOptsAlwaysHasMountAndPIDNamespaces(t *testing.T) {
	for _, mode := range []NetworkMode{NetworkNone, NetworkHost} {
		sopts := buildSpecOpts([]string{"sh"}, Options{
			WorkDir: "/",
			Network: mode,
		})
		sp := applySpecOpts(t, sopts)

		if !hasNamespaceType(sp, specs.MountNamespace) {
			t.Errorf("network=%s: expected mount namespace, not found", mode)
		}
		if !hasNamespaceType(sp, specs.PIDNamespace) {
			t.Errorf("network=%s: expected pid namespace, not found", mode)
		}
	}
}

// TestExecInvalidNetworkMode verifies that an unrecognised network mode
// returns an error rather than silently defaulting.
func TestExecInvalidNetworkMode(t *testing.T) {
	_, err := Exec(context.Background(), "fork-1", []string{"sh"}, Options{
		Network: NetworkMode("bridge"),
	})
	if err == nil {
		t.Fatal("expected error for invalid network mode, got nil")
	}
}

// applySpecOpts applies a list of oci.SpecOpts to a minimal spec and returns
// the result. It uses nil context and client; opts that fail are skipped (they
// typically require a live containerd daemon).
func applySpecOpts(t *testing.T, sopts []oci.SpecOpts) *specs.Spec {
	t.Helper()
	sp := &specs.Spec{
		Linux: &specs.Linux{},
		Process: &specs.Process{
			Env: []string{},
		},
	}
	c := &containers.Container{}
	for _, o := range sopts {
		if err := o(context.Background(), nil, c, sp); err != nil {
			// Some opts require a live client/snapshot; skip those.
			continue
		}
	}
	return sp
}

// hasNamespaceType returns true if the spec contains a namespace of the given type.
func hasNamespaceType(sp *specs.Spec, t specs.LinuxNamespaceType) bool {
	if sp.Linux == nil {
		return false
	}
	for _, ns := range sp.Linux.Namespaces {
		if ns.Type == t {
			return true
		}
	}
	return false
}
