// gc_test.go — unit tests for the gc cobra command.
//
// These tests exercise the CLI layer: argument validation and help text.
// They do not require a live containerd daemon; the gc command's RunE only
// dials containerd after cobra argument parsing succeeds.
//
// Tests that exercise the full GC lifecycle (TTL/LRU eviction, bytes reclaimed)
// live in the integration test suite and require a running containerd daemon.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 6 (GC, test plan)
//   - docs/architecture.md §5 OD-3 (fork GC scheduling)
package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestGCRejectsPositionalArgs verifies that supplying positional arguments
// produces a cobra usage error.
func TestGCRejectsPositionalArgs(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"gc", "unexpected-arg"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when positional arg supplied to gc, got nil")
	}
}

// TestGCAppearsInHelp verifies the gc command is documented in the root
// --help output (regression guard against accidental de-registration).
func TestGCAppearsInHelp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--help"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "gc") {
		t.Errorf("root --help missing 'gc' subcommand; got:\n%s", output)
	}
}

// TestGCHelpText verifies that the gc subcommand help text documents the
// key behaviours: per-eviction JSON, summary JSON, TTL, and LRU.
func TestGCHelpText(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"gc", "--help"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	_ = rootCmd.Execute()

	output := buf.String()

	checks := []struct {
		needle string
		desc   string
	}{
		{"forks_evicted", "help should document forks_evicted JSON field"},
		{"bytes_reclaimed", "help should document bytes_reclaimed JSON field"},
		{"ttl", "help should mention TTL eviction"},
		{"lru", "help should mention LRU eviction"},
		{"--gc-ttl", "help should document --gc-ttl flag"},
		{"--gc-max-disk", "help should document --gc-max-disk flag"},
	}
	for _, tc := range checks {
		if !strings.Contains(strings.ToLower(output), strings.ToLower(tc.needle)) {
			t.Errorf("%s; got:\n%s", tc.desc, output)
		}
	}
}

// TestGCTTLFlagDefault verifies that --gc-ttl defaults to 24h via the root
// command's persistent flag registration.
func TestGCTTLFlagDefault(t *testing.T) {
	f := rootCmd.PersistentFlags().Lookup("gc-ttl")
	if f == nil {
		t.Fatal("--gc-ttl persistent flag not registered on root command")
	}
	if f.DefValue != "24h0m0s" {
		t.Errorf("--gc-ttl default = %q, want \"24h0m0s\"", f.DefValue)
	}
}

// TestGCMaxDiskFlagRegistered verifies that --gc-max-disk is registered as a
// persistent flag on the root command.
func TestGCMaxDiskFlagRegistered(t *testing.T) {
	f := rootCmd.PersistentFlags().Lookup("gc-max-disk")
	if f == nil {
		t.Fatal("--gc-max-disk persistent flag not registered on root command")
	}
}
