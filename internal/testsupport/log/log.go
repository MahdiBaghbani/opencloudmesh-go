package log

import (
	"log/slog"
)

// DiscardLogger returns a logger that discards output at error level or above.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
