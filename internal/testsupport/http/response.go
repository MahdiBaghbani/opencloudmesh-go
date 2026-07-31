// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package http

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// MustClose closes c and reports failures through t. Use with defer in tests.
func MustClose(t *testing.T, c io.Closer) {
	t.Helper()

	if c == nil {
		return
	}

	if err := c.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// MustEncodeJSON writes v as JSON to w and reports failures through t.
// Errorf (not Fatalf) because mock handlers run on httptest server goroutines.
func MustEncodeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode json: %v", err)
	}
}

// MustMarshalJSON marshals v and fails the test when encoding fails.
func MustMarshalJSON(t *testing.T, v any) []byte {
	t.Helper()

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}

	return b
}

// MustWrite writes b to w and reports failures through t. Errorf (not Fatalf)
// because mock handlers run on httptest server goroutines.
func MustWrite(t *testing.T, w http.ResponseWriter, b []byte) {
	t.Helper()

	if _, err := w.Write(b); err != nil {
		t.Errorf("write response: %v", err)
	}
}

// WriteJSON encodes v as JSON. On failure it responds with HTTP 500 so stub handlers fail visibly.
func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "encode json: "+err.Error(), http.StatusInternalServerError)
	}
}
