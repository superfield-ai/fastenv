package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/superfield-ai/fastenv/internal/snapshotter"
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

// TestSnapshotterFlagDefault verifies that the global --snapshotter flag
// defaults to "overlayfs".
func TestSnapshotterFlagDefault(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("snapshotter")
	if flag == nil {
		t.Fatal("--snapshotter flag not registered on root command")
	}
	if flag.DefValue != "overlayfs" {
		t.Errorf("--snapshotter default: got %q, want %q", flag.DefValue, "overlayfs")
	}
}

// TestSnapshotterFlagUnknownDriver verifies that selecting an unregistered
// driver returns a descriptive error wrapping ErrUnknownDriver rather than
// panicking. This is the acceptance criterion from issue #3:
//
//	"Swapping --snapshotter to an unimplemented value returns a clear error
//	 rather than a panic."
func TestSnapshotterFlagUnknownDriver(t *testing.T) {
	// Set the global flag variable directly (simulates --snapshotter=bogus).
	original := snapshotterName
	snapshotterName = "bogus-driver"
	t.Cleanup(func() { snapshotterName = original })

	_, err := newSnapshotter()
	if err == nil {
		t.Fatal("expected error for unknown driver, got nil")
	}
	if !errors.Is(err, snapshotter.ErrUnknownDriver) {
		t.Errorf("expected error wrapping ErrUnknownDriver, got: %v", err)
	}
}

// TestSnapshotterRegisteredDrivers verifies that the expected drivers are
// available in the registry (overlayfs, stargz, nydus).
func TestSnapshotterRegisteredDrivers(t *testing.T) {
	drivers := snapshotter.Drivers()
	want := map[string]bool{"overlayfs": true, "stargz": true, "nydus": true}
	for _, d := range drivers {
		delete(want, d)
	}
	if len(want) > 0 {
		t.Errorf("missing expected drivers: %v", want)
	}
}
