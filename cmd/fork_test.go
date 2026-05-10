// fork_test.go — unit tests for the fork cobra command.
//
// These tests exercise the CLI layer: argument parsing, flag validation, and
// help text. They do not require a live containerd daemon; the fork command's
// RunE only returns an error before dialing containerd when required flags are
// missing.
//
// Note: the test package uses the shared rootCmd instance. To avoid cobra flag
// value persistence across test runs, each test resets both --base and --name
// flags to their zero value via SetArgs. Tests that need a fresh flag state
// explicitly set all relevant flags.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 2 (fork, test plan)
//   - docs/scout/phase1-findings.md §1 Phase B (snapshot Prepare for fork)
package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// resetForkFlags resets the --base and --name cobra flags on the fork
// subcommand to their zero values. This prevents flag value persistence across
// test runs sharing the package-level rootCmd.
func resetForkFlags(t *testing.T) {
	t.Helper()
	forkCmd := rootCmd.Commands()
	for _, c := range forkCmd {
		if c.Use == "fork" {
			if f := c.Flags().Lookup("base"); f != nil {
				_ = f.Value.Set("")
			}
			if f := c.Flags().Lookup("name"); f != nil {
				_ = f.Value.Set("")
			}
			return
		}
	}
}

// TestForkRequiresBaseFlag verifies that omitting --base produces a clear
// error message rather than a panic or an obscure containerd error.
func TestForkRequiresBaseFlag(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"fork", "--name", "agent-1"})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		resetForkFlags(t)
	})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when --base is missing, got nil")
	}
	if !strings.Contains(err.Error(), "--base is required") {
		t.Errorf("expected error to mention --base, got: %v", err)
	}
}

// TestForkRequiresNameFlag verifies that omitting --name produces a clear
// error message.
func TestForkRequiresNameFlag(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"fork", "--base", "my-workspace"})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		resetForkFlags(t)
	})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when --name is missing, got nil")
	}
	if !strings.Contains(err.Error(), "--name is required") {
		t.Errorf("expected error to mention --name, got: %v", err)
	}
}

// TestForkAppearsInHelp verifies the fork command is documented in the --help
// output (regression guard against accidental de-registration).
func TestForkAppearsInHelp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"fork", "--help"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "--base") {
		t.Errorf("fork --help missing --base flag; got:\n%s", output)
	}
	if !strings.Contains(output, "--name") {
		t.Errorf("fork --help missing --name flag; got:\n%s", output)
	}
}

// TestForkHelpMentionsLatency verifies the fork command help text documents
// the p50/p95 latency target.
func TestForkHelpMentionsLatency(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"fork", "--help"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "p95") {
		t.Errorf("fork --help should mention p95 latency target; got:\n%s", output)
	}
}
