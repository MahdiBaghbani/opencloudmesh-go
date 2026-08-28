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

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func newSessionTestRouter(t *testing.T, h *Handler) chi.Router {
	t.Helper()

	r := chi.NewRouter()
	r.Method(http.MethodGet, RouteAPISession, http.HandlerFunc(h.HandleSession))

	return r
}

func seedSessionRow(t *testing.T, store *validatorcore.Core, row *validatorcore.TestRun) {
	t.Helper()

	if err := store.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func doPoll(t *testing.T, h *Handler, runID string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/"+runID, nil)
	rec := httptest.NewRecorder()
	newSessionTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	return rec
}

func pollSession(t *testing.T, h *Handler, runID string) map[string]json.RawMessage {
	t.Helper()

	rec := doPoll(t, h, runID)

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	return payload
}

func pollNextInstruction(t *testing.T, payload map[string]json.RawMessage) string {
	t.Helper()

	var next string
	if err := json.Unmarshal(payload["nextInstruction"], &next); err != nil {
		t.Fatalf("nextInstruction: %v", err)
	}

	return next
}
