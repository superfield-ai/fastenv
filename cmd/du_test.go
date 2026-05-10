// du_test.go — unit tests for the du cobra command.
//
// These tests exercise the CLI layer: argument parsing and help text.
// They do not require a live containerd daemon.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 4 (du), Phase 5 (shared caches), Phase 5 (quotas)
//   - docs/architecture.md §5 OD-4 (quota enforcement)
package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestDuRequiresForkIDArg verifies that omitting the fork-id positional
// argument returns a usage error.
func TestDuRequiresForkIDArg(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"du"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when fork-id is missing, got nil")
	}
}

// TestDuAppearsInHelp verifies the du command is documented in the --help
// output (regression guard against accidental de-registration).
func TestDuAppearsInHelp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"du", "--help"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "fork-id") {
		t.Errorf("du --help missing fork-id argument; got:\n%s", output)
	}
}

// TestDuHelpMentionsCacheBreakdown verifies that the du command help text
// documents that cache writes are reported separately from workspace writes.
func TestDuHelpMentionsCacheBreakdown(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"du", "--help"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "cache") {
		t.Errorf("du --help should mention cache writes; got:\n%s", output)
	}
}

// TestDuHelpMentionsQuota verifies that du help text describes quota warning
// behaviour so users understand the soft/hard distinction.
func TestDuHelpMentionsQuota(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"du", "--help"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "quota") {
		t.Errorf("du --help should mention quota; got:\n%s", output)
	}
}
