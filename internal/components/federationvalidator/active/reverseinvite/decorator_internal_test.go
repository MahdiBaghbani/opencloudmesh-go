// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestObservingWriter_CaptureNeverOvershoots(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	w := &observingWriter{ResponseWriter: rec}

	// Three writes cross the cap: the second is clipped to the remaining
	// budget, the third is fully dropped from the capture.
	chunks := []int{32 << 10, 64 << 10, 16 << 10}
	total := 0

	for _, size := range chunks {
		n, err := w.Write(bytes.Repeat([]byte("a"), size))
		if err != nil {
			t.Fatalf("write %d bytes: %v", size, err)
		}

		if n != size {
			t.Fatalf("write returned n = %d, want %d (passthrough must stay full)", n, size)
		}

		total += size
	}

	if got := len(w.captured()); got != maxObservedBodyBytes {
		t.Fatalf("captured = %d bytes, want exactly %d", got, maxObservedBodyBytes)
	}

	if rec.Body.Len() != total {
		t.Fatalf("response body = %d bytes, want %d (full passthrough)", rec.Body.Len(), total)
	}
}

func TestObservingWriter_CaptureExactCap(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	w := &observingWriter{ResponseWriter: rec}

	if _, err := w.Write(bytes.Repeat([]byte("b"), maxObservedBodyBytes)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := len(w.captured()); got != maxObservedBodyBytes {
		t.Fatalf("captured = %d bytes, want exactly %d", got, maxObservedBodyBytes)
	}
}
