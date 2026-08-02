// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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
