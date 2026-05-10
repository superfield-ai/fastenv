// Package quota_test tests quota parsing, formatting, and mode detection.
package quota_test

import (
	"testing"

	"github.com/superfield-ai/fastenv/internal/quota"
)

// TestParse verifies that human-readable size strings are correctly converted
// to byte counts.
func TestParse(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{"10MiB", 10 * 1024 * 1024, false},
		{"1GiB", 1 * 1024 * 1024 * 1024, false},
		{"512KiB", 512 * 1024, false},
		{"1TiB", 1024 * 1024 * 1024 * 1024, false},
		{"100MB", 100_000_000, false},
		{"1GB", 1_000_000_000, false},
		{"1KB", 1_000, false},
		{"1B", 1, false},
		{"1024", 1024, false},
		{"0", 0, false},
		{"", 0, true},
		{"-1", 0, true},
		{"-10MiB", 0, true},
		{"abc", 0, true},
		{"10XiB", 0, true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			got, err := quota.Parse(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q): expected error, got nil (value %d)", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q): unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("Parse(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// TestFormat verifies human-readable formatting of byte counts.
func TestFormat(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{10 * 1024 * 1024, "10.0 MiB"},
		{1024 * 1024 * 1024, "1.0 GiB"},
		{1024 * 1024 * 1024 * 1024, "1.0 TiB"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.want, func(t *testing.T) {
			got := quota.Format(tc.bytes)
			if got != tc.want {
				t.Errorf("Format(%d) = %q, want %q", tc.bytes, got, tc.want)
			}
		})
	}
}

// TestDetectMode verifies that DetectMode returns a valid mode without panicking.
// The actual mode depends on the host configuration; we only assert the type.
func TestDetectMode(t *testing.T) {
	mode := quota.DetectMode("/tmp")
	if mode != quota.ModeSoft && mode != quota.ModeHard {
		t.Errorf("DetectMode returned unexpected mode: %q", mode)
	}
}

// TestParseRoundTrip verifies that Parse ∘ Format = identity for even byte counts.
func TestParseRoundTrip(t *testing.T) {
	inputs := []string{"10MiB", "1GiB", "512KiB", "2TiB"}
	for _, s := range inputs {
		bytes, err := quota.Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		formatted := quota.Format(bytes)
		reparsed, err := quota.Parse(formatted)
		if err != nil {
			t.Fatalf("Parse(Format(%q)) = Parse(%q): %v", s, formatted, err)
		}
		if reparsed != bytes {
			t.Errorf("round-trip %q: got %d, want %d (via %q)", s, reparsed, bytes, formatted)
		}
	}
}
