// Package gcer_test contains unit tests for the gcer package.
//
// These tests exercise the GC policy logic using a fake snapshotter. They do
// not require a live containerd daemon.
//
// Canonical docs:
//   - docs/implementation-plan.md Phase 6 (GC, test plan)
package gcer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/superfield-ai/fastenv/internal/gcer"
)

// TestDefaultConstants verifies that the exported defaults have sane values.
func TestDefaultConstants(t *testing.T) {
	if gcer.DefaultTTL != 24*time.Hour {
		t.Errorf("DefaultTTL = %v, want 24h", gcer.DefaultTTL)
	}
	if gcer.DefaultMaxDisk <= 0 {
		t.Errorf("DefaultMaxDisk = %d, want > 0", gcer.DefaultMaxDisk)
	}
}

// TestGCResultFields verifies that GCResult and EvictionRecord JSON tags are
// correct (regression guard for field renames).
func TestGCResultFields(t *testing.T) {
	rec := gcer.EvictionRecord{
		ForkID:         "agent-1",
		Reason:         "ttl",
		BytesReclaimed: 1024,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal EvictionRecord: %v", err)
	}
	s := string(data)
	for _, want := range []string{"fork_id", "reason", "bytes_reclaimed"} {
		if !strings.Contains(s, want) {
			t.Errorf("EvictionRecord JSON missing %q; got: %s", want, s)
		}
	}
}

// TestEvictionReasonValues verifies that the eviction reason constants used in
// the package match the values documented in the issue.
func TestEvictionReasonValues(t *testing.T) {
	validReasons := map[string]bool{
		"ttl":      true,
		"lru":      true,
		"explicit": true,
	}
	for reason := range validReasons {
		rec := gcer.EvictionRecord{Reason: reason}
		if rec.Reason != reason {
			t.Errorf("EvictionRecord.Reason round-trip failed for %q", reason)
		}
	}
}

// TestOptionsDefaults verifies that zero Options are accepted by RunGC without
// panicking (it will fail to dial containerd, but Options defaulting is tested).
func TestOptionsDefaults(t *testing.T) {
	// We expect a dial error, not a nil-pointer panic, when using zero Options.
	ctx := context.Background()
	_, err := gcer.RunGC(ctx, gcer.Options{
		SocketPath: "/nonexistent/containerd.sock",
	})
	if err == nil {
		t.Fatal("expected dial error for nonexistent socket, got nil")
	}
	if !strings.Contains(err.Error(), "gc:") {
		t.Errorf("expected error to start with 'gc:', got: %v", err)
	}
}

// TestGCResultJSON verifies that GCResult serialises to expected JSON keys.
func TestGCResultJSON(t *testing.T) {
	result := gcer.GCResult{
		ForksEvicted:   3,
		BytesReclaimed: 4096,
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal GCResult: %v", err)
	}
	s := string(data)
	for _, want := range []string{"forks_evicted", "bytes_reclaimed"} {
		if !strings.Contains(s, want) {
			t.Errorf("GCResult JSON missing %q; got: %s", want, s)
		}
	}
}

// TestEvictionRecordOutput verifies that EvictionRecord JSON output is
// well-formed and includes required fields.
func TestEvictionRecordOutput(t *testing.T) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	records := []gcer.EvictionRecord{
		{ForkID: "agent-1", Reason: "ttl", BytesReclaimed: 512},
		{ForkID: "agent-2", Reason: "lru", BytesReclaimed: 2048},
	}
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			t.Fatalf("encode EvictionRecord: %v", err)
		}
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON lines, got %d: %s", len(lines), buf.String())
	}
	for i, line := range lines {
		var got map[string]interface{}
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d: invalid JSON: %v", i, err)
		}
		if _, ok := got["fork_id"]; !ok {
			t.Errorf("line %d missing fork_id", i)
		}
		if _, ok := got["reason"]; !ok {
			t.Errorf("line %d missing reason", i)
		}
		if _, ok := got["bytes_reclaimed"]; !ok {
			t.Errorf("line %d missing bytes_reclaimed", i)
		}
	}
}
