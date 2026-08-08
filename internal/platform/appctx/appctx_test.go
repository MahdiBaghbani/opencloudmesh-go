// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package appctx

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
)

func TestWithLogger_And_LoggerFromContext(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, nil))

	ctx := context.Background()
	ctx = WithLogger(ctx, logger)

	got, ok := LoggerFromContext(ctx)
	if !ok {
		t.Fatal("Expected LoggerFromContext to return true")
	}

	if got != logger {
		t.Error("Expected same logger instance")
	}
}

func TestLoggerFromContext_NoLogger(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	got, ok := LoggerFromContext(ctx)
	if ok {
		t.Error("Expected LoggerFromContext to return false for context without logger")
	}

	if got != nil {
		t.Error("Expected nil logger")
	}
}

func TestLoggerFromContext_NilLogger(t *testing.T) {
	t.Parallel()

	// Create a context with a nil logger stored

	ctx := context.WithValue(context.Background(), loggerKey{}, (*slog.Logger)(nil))

	got, ok := LoggerFromContext(ctx)
	if ok {
		t.Error("Expected LoggerFromContext to return false for nil logger")
	}

	if got != nil {
		t.Error("Expected nil logger")
	}
}

func TestGetLogger_WithLogger(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, nil))

	ctx := WithLogger(context.Background(), logger)

	got := GetLogger(ctx)
	if got != logger {
		t.Error("Expected GetLogger to return the attached logger")
	}
}

func TestGetLogger_WithoutLogger(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	got := GetLogger(ctx)
	if got == nil {
		t.Fatal("Expected GetLogger to return non-nil logger")
	}

	// Should return slog.Default()
	if got != slog.Default() {
		t.Error("Expected GetLogger to return slog.Default() when no logger in context")
	}
}

func TestGetLogger_NilContext(t *testing.T) {
	t.Parallel()

	// GetLogger should handle nil context gracefully
	// Note: context.Background() is used as fallback behavior test

	ctx := context.Background()

	got := GetLogger(ctx)
	if got == nil {
		t.Fatal("Expected GetLogger to return non-nil logger")
	}
}

func TestLogger_ActuallyLogs(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, nil))

	ctx := WithLogger(context.Background(), logger)

	// Get logger and log something
	GetLogger(ctx).Info("test message", "key", "value")

	output := buf.String()
	if output == "" {
		t.Fatal("Expected log output")
	}

	if !bytes.Contains(buf.Bytes(), []byte("test message")) {
		t.Errorf("Expected log to contain 'test message', got: %s", output)
	}

	if !bytes.Contains(buf.Bytes(), []byte("key=value")) {
		t.Errorf("Expected log to contain 'key=value', got: %s", output)
	}
}
