// build_base_test.go — unit tests for the build-base cobra command.
//
// These tests exercise the CLI layer: argument parsing, flag validation, and
// the structured JSON output contract.  They do not require a live containerd
// daemon; integration behaviour is tested in internal/builder/builder_test.go.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 2 (build-base, test plan)
package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestBuildBaseRequiresNameFlag verifies that omitting --name produces a clear
// error message rather than a panic or an obscure error.
func TestBuildBaseRequiresNameFlag(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"build-base", "/tmp"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err := rootCmd.Execute()
	// Execute returns an error for invalid arguments.
	if err == nil {
		t.Fatal("expected error when --name is missing, got nil")
	}
	if !strings.Contains(err.Error(), "--name is required") {
		t.Errorf("expected error to mention --name, got: %v", err)
	}
}

// TestBuildBaseRequiresSourceDir verifies that passing no positional arguments
// returns a usage error.
func TestBuildBaseRequiresSourceDir(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"build-base"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when no source-dir is provided, got nil")
	}
}

// TestBuildBaseAppearsInHelp verifies the build-base command is documented in
// the --help output (regression guard against accidental de-registration).
func TestBuildBaseAppearsInHelp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"build-base", "--help"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "--name") {
		t.Errorf("build-base --help missing --name flag; got:\n%s", output)
	}
	if !strings.Contains(output, "source-dir") {
		t.Errorf("build-base --help missing source-dir argument; got:\n%s", output)
	}
}
