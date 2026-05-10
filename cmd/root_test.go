package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestRootHelp verifies that fastenv --help lists all required subcommands.
// This is an acceptance criterion from issue #2.
func TestRootHelp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--help"})

	// Reset args after test so other tests start clean.
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	// --help causes a special exit; ignore the returned error.
	_ = rootCmd.Execute()

	output := buf.String()

	// All subcommands required by the issue scope must appear in help output.
	requiredSubcommands := []string{
		"build-base",
		"fork",
		"exec",
		"diff",
		"du",
		"export-patch",
		"discard",
		"gc",
		"bench",
	}

	for _, sub := range requiredSubcommands {
		if !strings.Contains(output, sub) {
			t.Errorf("fastenv --help missing subcommand %q; got:\n%s", sub, output)
		}
	}
}
