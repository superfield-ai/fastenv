// Package logger implements structured JSON logging for fastenv CLI commands.
//
// All CLI commands emit structured JSON log lines to stderr, controlled by the
// --log-level global flag. Each line contains:
//
//	{"level":"info","ts":"2006-01-02T15:04:05.000Z07:00","op":"fork","duration":"12.3ms","fork_id":"agent-1"}
//
// Log levels follow slog conventions: debug, info, warn, error.
// The default level is "info" — debug lines are suppressed unless --log-level=debug.
//
// Canonical docs:
//   - docs/architecture.md §5 OD-1 (observability tooling)
//   - docs/implementation-plan.md Phase 6 (Observability)
package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Level represents a log severity level.
type Level int

const (
	// LevelDebug is verbose diagnostic output.
	LevelDebug Level = iota
	// LevelInfo is the default level for normal operational events.
	LevelInfo
	// LevelWarn is for unexpected but non-fatal events.
	LevelWarn
	// LevelError is for fatal or error events.
	LevelError
)

// ParseLevel converts a level string to a Level constant.
// Returns LevelInfo and an error for unrecognized strings.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, nil
	case "info", "":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level %q: must be debug, info, warn, or error", s)
	}
}

// String returns the string representation of a Level.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}

// Logger emits structured JSON log lines to an io.Writer (typically stderr).
type Logger struct {
	level Level
	out   io.Writer
}

// New creates a new Logger at the given level writing to out.
// If out is nil, os.Stderr is used.
func New(level Level, out io.Writer) *Logger {
	if out == nil {
		out = os.Stderr
	}
	return &Logger{level: level, out: out}
}

// logLine is the JSON structure emitted for each log event.
type logLine struct {
	Level     string `json:"level"`
	Timestamp string `json:"ts"`
	// Op is the CLI operation name (e.g. "fork", "exec", "bench").
	Op string `json:"op,omitempty"`
	// Message is a human-readable description of the event.
	Message string `json:"msg,omitempty"`
	// Duration is the wall-clock time for the operation (e.g. "12.3ms").
	Duration string `json:"duration,omitempty"`
	// Extra holds additional key-value pairs specific to the operation.
	Extra map[string]any `json:"-"`
}

// Fields is a map of additional key-value pairs to include in a log line.
type Fields map[string]any

// emit writes a JSON log line if level >= logger level.
func (l *Logger) emit(level Level, op, msg string, fields Fields) {
	if level < l.level {
		return
	}

	line := logLine{
		Level:     level.String(),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Op:        op,
		Message:   msg,
	}

	// Build a merged map: start from fixed fields, overlay extras.
	m := map[string]any{
		"level": line.Level,
		"ts":    line.Timestamp,
	}
	if line.Op != "" {
		m["op"] = line.Op
	}
	if line.Message != "" {
		m["msg"] = line.Message
	}
	for k, v := range fields {
		m[k] = v
	}

	data, err := json.Marshal(m)
	if err != nil {
		// Fallback: write a minimal error line.
		fmt.Fprintf(l.out, `{"level":"error","ts":%q,"msg":"logger marshal error","err":%q}`+"\n",
			line.Timestamp, err.Error())
		return
	}
	fmt.Fprintf(l.out, "%s\n", data)
}

// Debug emits a debug-level log line.
func (l *Logger) Debug(op, msg string, fields Fields) {
	l.emit(LevelDebug, op, msg, fields)
}

// Info emits an info-level log line.
func (l *Logger) Info(op, msg string, fields Fields) {
	l.emit(LevelInfo, op, msg, fields)
}

// Warn emits a warn-level log line.
func (l *Logger) Warn(op, msg string, fields Fields) {
	l.emit(LevelWarn, op, msg, fields)
}

// Error emits an error-level log line.
func (l *Logger) Error(op, msg string, fields Fields) {
	l.emit(LevelError, op, msg, fields)
}
