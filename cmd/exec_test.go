// exec_test.go — unit tests for the exec cobra command.
//
// These tests exercise the CLI layer: argument parsing, flag validation, help
// text, and the parseMemory helper. They do not require a live containerd
// daemon; exec's RunE dials containerd only after argument validation passes.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 3 (exec, test plan)
//   - docs/scout/phase1-findings.md §2 (crun integration path)
package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestExecRequiresArgs verifies that exec with no arguments returns a usage
// error, not a panic or a confusing containerd error.
func TestExecRequiresArgs(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"exec"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when exec is called without arguments, got nil")
	}
}

// TestExecAppearsInHelp verifies the exec command is documented in the --help
// output and mentions the key flags.
func TestExecAppearsInHelp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"exec", "--help"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	_ = rootCmd.Execute()

	output := buf.String()
	for _, want := range []string{"--cpu", "--memory", "--crun-path", "--network"} {
		if !strings.Contains(output, want) {
			t.Errorf("exec --help missing %q flag; output:\n%s", want, output)
		}
	}
}

// TestParseMemory validates the parseMemory helper for a range of inputs.
func TestParseMemory(t *testing.T) {
	cases := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"1024", 1024, false},
		{"512m", 512 * 1024 * 1024, false},
		{"512M", 512 * 1024 * 1024, false},
		{"1g", 1 * 1024 * 1024 * 1024, false},
		{"1G", 1 * 1024 * 1024 * 1024, false},
		{"4k", 4 * 1024, false},
		{"4K", 4 * 1024, false},
		{"256b", 256, false},
		{"256B", 256, false},
		{"abc", 0, true},
		{"-1", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseMemory(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("parseMemory(%q): expected error, got %d", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("parseMemory(%q): unexpected error: %v", tc.input, err)
				return
			}
			if got != tc.want {
				t.Errorf("parseMemory(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}
