package logger_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/superfield-ai/fastenv/internal/logger"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		input   string
		want    logger.Level
		wantErr bool
	}{
		{"debug", logger.LevelDebug, false},
		{"DEBUG", logger.LevelDebug, false},
		{"info", logger.LevelInfo, false},
		{"", logger.LevelInfo, false},
		{"warn", logger.LevelWarn, false},
		{"warning", logger.LevelWarn, false},
		{"error", logger.LevelError, false},
		{"invalid", logger.LevelInfo, true},
	}
	for _, tc := range cases {
		got, err := logger.ParseLevel(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseLevel(%q): wantErr=%v, got err=%v", tc.input, tc.wantErr, err)
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ParseLevel(%q): want %v, got %v", tc.input, tc.want, got)
		}
	}
}

func TestLoggerEmitsValidJSON(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(logger.LevelDebug, &buf)

	l.Info("fork", "fork created", logger.Fields{
		"fork_id":  "agent-1",
		"duration": "12.3ms",
	})

	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("expected log line, got empty output")
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("log line is not valid JSON: %v\nline: %s", err, line)
	}

	if m["level"] != "info" {
		t.Errorf("level: want %q, got %q", "info", m["level"])
	}
	if m["op"] != "fork" {
		t.Errorf("op: want %q, got %q", "fork", m["op"])
	}
	if m["fork_id"] != "agent-1" {
		t.Errorf("fork_id: want %q, got %q", "agent-1", m["fork_id"])
	}
	if _, ok := m["ts"]; !ok {
		t.Error("expected ts field in log line")
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	// Logger at Info level should suppress Debug lines.
	l := logger.New(logger.LevelInfo, &buf)

	l.Debug("test", "should be suppressed", nil)
	if buf.Len() > 0 {
		t.Errorf("debug line should be suppressed at info level, got: %s", buf.String())
	}

	l.Info("test", "should appear", nil)
	if buf.Len() == 0 {
		t.Error("info line should appear at info level")
	}
}

func TestLoggerMultipleLines(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(logger.LevelDebug, &buf)

	l.Debug("op1", "first", nil)
	l.Info("op2", "second", nil)
	l.Warn("op3", "third", nil)
	l.Error("op4", "fourth", nil)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 log lines, got %d", len(lines))
	}

	levels := []string{"debug", "info", "warn", "error"}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
			continue
		}
		if m["level"] != levels[i] {
			t.Errorf("line %d: want level %q, got %q", i, levels[i], m["level"])
		}
	}
}
