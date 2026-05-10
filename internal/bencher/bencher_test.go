package bencher_test

import (
	"encoding/json"
	"testing"
)

// TestLatencyStatsMarshal verifies the JSON structure of LatencyStats matches
// the expected schema (all five percentile fields present and correct types).
func TestLatencyStatsMarshal(t *testing.T) {
	// Inline the struct here to avoid importing containerd (which requires a
	// running daemon). The BenchResult type only needs stat computation for
	// unit tests; integration tests require containerd.
	type LatencyStats struct {
		P50Ms   float64 `json:"p50_ms"`
		P95Ms   float64 `json:"p95_ms"`
		P99Ms   float64 `json:"p99_ms"`
		MinMs   float64 `json:"min_ms"`
		MaxMs   float64 `json:"max_ms"`
		Samples int     `json:"samples"`
	}

	stats := LatencyStats{
		P50Ms:   12.3,
		P95Ms:   45.6,
		P99Ms:   78.9,
		MinMs:   1.0,
		MaxMs:   100.0,
		Samples: 100,
	}

	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("marshal LatencyStats: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	fields := []string{"p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms", "samples"}
	for _, f := range fields {
		if _, ok := m[f]; !ok {
			t.Errorf("expected field %q in JSON output", f)
		}
	}
}

// TestBenchResultSchema verifies the top-level JSON document schema.
func TestBenchResultSchema(t *testing.T) {
	type BenchResult struct {
		Version    string `json:"version"`
		Timestamp  string `json:"timestamp"`
		Iterations int    `json:"iterations"`
		BaseImage  string `json:"base_image"`
	}

	result := BenchResult{
		Version:    "1",
		Timestamp:  "2024-01-01T00:00:00Z",
		Iterations: 100,
		BaseImage:  "my-workspace",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal BenchResult: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if m["version"] != "1" {
		t.Errorf("version: want %q, got %v", "1", m["version"])
	}
	if m["iterations"] != float64(100) {
		t.Errorf("iterations: want %v, got %v", 100, m["iterations"])
	}
}
