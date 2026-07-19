package logutil

import (
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func TestCapturingLoggerConcurrentWrites(t *testing.T) {
	capture := NewCapturingLogger(slog.LevelDebug)

	const writers = 32
	var wg sync.WaitGroup
	wg.Add(writers)
	for range writers {
		go func() {
			defer wg.Done()
			capture.Logger.Debug("concurrent")
		}()
	}
	wg.Wait()

	if got := strings.Count(capture.Output(), "msg=concurrent"); got != writers {
		t.Fatalf("captured log count = %d, want %d", got, writers)
	}
}
