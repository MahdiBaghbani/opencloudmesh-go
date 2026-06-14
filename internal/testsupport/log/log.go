package log

import (
	"io"
	"log/slog"
)

// DiscardLogger returns a logger that discards output at error level or above.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}
