// Package logutil provides nil-safe logger helpers.
package logutil

import (
	"io"
	"log/slog"
)

// noop is a package-level discard logger, created once.
var noop = slog.New(slog.NewTextHandler(io.Discard, nil))

// Noop returns a logger that discards all output.
func Noop() *slog.Logger { return noop }

// NoopIfNil returns l when non-nil, otherwise a discard logger.
// Intended as the first line in constructors that accept *slog.Logger.
func NoopIfNil(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return noop
}
