package logutil

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
)

// CapturingLogger records slog output for tests.
type CapturingLogger struct {
	Logger *slog.Logger
	buf    *bytes.Buffer
	mu     sync.Mutex
}

// NewCapturingLogger returns a logger writing to an in-memory buffer.
func NewCapturingLogger(level slog.Level) *CapturingLogger {
	capture := &CapturingLogger{buf: &bytes.Buffer{}}
	capture.Logger = slog.New(slog.NewTextHandler(capture, &slog.HandlerOptions{Level: level}))

	return capture
}

// Write serializes slog writes with reads and resets of the capture buffer.
func (c *CapturingLogger) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.buf.Write(p)
}

// Output returns captured log text.
func (c *CapturingLogger) Output() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.buf.String()
}

// Contains reports whether any captured line contains needle.
func (c *CapturingLogger) Contains(needle string) bool {
	return strings.Contains(c.Output(), needle)
}

// ContainsAny reports whether captured output contains any needle.
func (c *CapturingLogger) ContainsAny(needles ...string) bool {
	out := c.Output()
	for _, needle := range needles {
		if strings.Contains(out, needle) {
			return true
		}
	}

	return false
}

// Reset clears captured output.
func (c *CapturingLogger) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.buf.Reset()
}
