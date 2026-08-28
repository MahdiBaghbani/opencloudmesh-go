// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteJSON_EncodeFailureDoesNotWriteResponse(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	writeJSON(rec, nil, http.StatusOK, make(chan int))

	if rec.Body.Len() != 0 {
		t.Fatalf("body length = %d, want 0 on encode failure", rec.Body.Len())
	}

	if ct := rec.Header().Get("Content-Type"); ct != "" {
		t.Fatalf("content-type = %q, want empty (headers not committed)", ct)
	}
}

func TestWriteJSON_SuccessWritesOnce(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	writeJSON(rec, nil, http.StatusOK, map[string]string{"id": "run-1"})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["id"] != "run-1" {
		t.Fatalf("id = %q, want run-1", payload["id"])
	}
}
