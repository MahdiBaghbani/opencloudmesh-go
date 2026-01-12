// Package appctx provides context-based utilities for cross-cutting concerns.
// Mimics Reva's "appctx logger from context" pattern, built on slog.
package appctx

import (
	"context"
	"log/slog"
)

type loggerKey struct{}

// WithLogger attaches a logger to the context.
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, l)
}

// LoggerFromContext returns the logger from the context (if present).
func LoggerFromContext(ctx context.Context) (*slog.Logger, bool) {
	l, ok := ctx.Value(loggerKey{}).(*slog.Logger)
	return l, ok && l != nil
}

// GetLogger returns the logger from the context, or slog.Default() if missing.
func GetLogger(ctx context.Context) *slog.Logger {
	if l, ok := LoggerFromContext(ctx); ok {
		return l
	}
	return slog.Default()
}
