// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package logutil

import (
	"bytes"
	"fmt"
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

	n, err := c.buf.Write(p)
	if err != nil {
		return n, fmt.Errorf("logutil: capture log: %w", err)
	}

	return n, nil
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
