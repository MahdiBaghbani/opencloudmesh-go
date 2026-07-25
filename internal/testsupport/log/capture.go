package log

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// LogCapture accumulates slog output for test assertions.
type LogCapture struct {
	buf bytes.Buffer
}

// NewLogCapture returns a slog.Logger writing JSON at warn level and above and a
// capture buffer for substring assertions. Info and Debug records are filtered out.
func NewLogCapture(t testing.TB) (*slog.Logger, *LogCapture) {
	t.Helper()
	c := &LogCapture{}
	logger := slog.New(slog.NewJSONHandler(c, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return logger, c
}

func (c *LogCapture) Write(p []byte) (n int, err error) {
	return c.buf.Write(p)
}

// Contains reports whether the captured log output contains substr.
func (c *LogCapture) Contains(substr string) bool {
	return strings.Contains(c.buf.String(), substr)
}
