// discard_test.go — unit tests for the discard cobra command.
//
// These tests exercise the CLI layer: argument parsing, argument validation,
// and help text. They do not require a live containerd daemon; the discard
// command's RunE only dials containerd after cobra argument parsing succeeds,
// so argument-level errors are catchable in pure unit tests.
//
// Tests that exercise the full discard lifecycle (snapshot removal, GC,
// bytes-freed reporting) live in the integration test suite and require a
// running containerd daemon.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 2 (discard, test plan)
//   - docs/scout/phase1-findings.md §1 Phase C (snapshot Remove)
package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestDiscardRequiresForkID verifies that omitting the positional <fork-id>
// argument produces a cobra usage error rather than a panic or an obscure
// containerd error.
func TestDiscardRequiresForkID(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"discard"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when fork-id is missing, got nil")
	}
	// cobra reports argument count errors via the Usage message
	if !strings.Contains(err.Error(), "arg") && !strings.Contains(err.Error(), "argument") && !strings.Contains(err.Error(), "accepts") {
		t.Errorf("expected argument error, got: %v", err)
	}
}

// TestDiscardRejectsTooManyArgs verifies that passing more than one positional
// argument produces a cobra usage error.
func TestDiscardRejectsTooManyArgs(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"discard", "agent-1", "agent-2"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for too many args, got nil")
	}
}

// TestDiscardAppearsInHelp verifies the discard command is documented in the
// root --help output (regression guard against accidental de-registration).
func TestDiscardAppearsInHelp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--help"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "discard") {
		t.Errorf("root --help missing 'discard' subcommand; got:\n%s", output)
	}
}

// TestDiscardHelpText verifies that the discard subcommand help text contains
// key documentation: the JSON output format, idempotency guarantee, and the
// note about task lifecycle.
func TestDiscardHelpText(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"discard", "--help"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	_ = rootCmd.Execute()

	output := buf.String()

	checks := []struct {
		needle string
		desc   string
	}{
		{"fork-id", "usage line should mention <fork-id>"},
		{"writable_layer_bytes_freed", "help should document JSON field writable_layer_bytes_freed"},
		{"Idempotent", "help should document idempotency"},
		{"GC", "help should mention GC pass"},
	}
	for _, tc := range checks {
		if !strings.Contains(output, tc.needle) {
			t.Errorf("%s; got:\n%s", tc.desc, output)
		}
	}
}
