// Package duer exercises humanBytes formatting.
// These tests do not require a live containerd daemon.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 4 (du, test plan)
package duer

import (
	"testing"
)

// TestHumanBytes verifies that humanBytes produces correct IEC representations
// for boundary values. A freshly created fork with no writes reports "0 B",
// and a fork with ~1 MiB of writes reports "1 MiB".
func TestHumanBytes(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		// Near-zero: fresh fork with no writes.
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		// KiB boundary.
		{1024, "1 KiB"},
		{1536, "1.5 KiB"},
		// 1 MiB: acceptance criterion "after writing a 1 MiB file, du reports ≈ 1 MiB".
		{1024 * 1024, "1 MiB"},
		// 1.5 MiB fractional.
		{int64(1.5 * 1024 * 1024), "1.5 MiB"},
		// GiB.
		{1024 * 1024 * 1024, "1 GiB"},
	}

	for _, tc := range tests {
		got := humanBytes(tc.bytes)
		if got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.bytes, got, tc.want)
		}
	}
}
