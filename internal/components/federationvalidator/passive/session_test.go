// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func newSessionTestRouter(t *testing.T, h *Handler) chi.Router {
	t.Helper()

	r := chi.NewRouter()
	r.Method(http.MethodGet, RouteAPISession, http.HandlerFunc(h.HandleSession))

	return r
}

func TestHandleSession_ReturnsStateAndTsOnly(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-poll"

	row := &validatorcore.TestRun{
		TestRunID:   runID,
		State:       validatorcore.StatePassiveComplete,
		SessionKind: validatorcore.SessionKindPassiveOnly,
		TargetHost:  "peer.example",
		CreatedAt:   now,
		UpdatedAt:   now + 42,
	}

	if err := store.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/"+runID, nil)
	rec := httptest.NewRecorder()
	newSessionTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	assertExactKeys(t, payload, []string{"state", "ts"})

	var state string
	if err := json.Unmarshal(payload["state"], &state); err != nil {
		t.Fatalf("state: %v", err)
	}

	if state != validatorcore.StatePassiveComplete {
		t.Fatalf("state = %q, want %q", state, validatorcore.StatePassiveComplete)
	}

	var ts int64
	if err := json.Unmarshal(payload["ts"], &ts); err != nil {
		t.Fatalf("ts: %v", err)
	}

	if ts != now+42 {
		t.Fatalf("ts = %d, want %d", ts, now+42)
	}
}

func TestHandleSession_UnknownID404(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/missing-run", nil)
	rec := httptest.NewRecorder()
	newSessionTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeSessionNotFound {
		t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeSessionNotFound)
	}
}

func TestHandleSession_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/session/run-1", nil)
	rec := httptest.NewRecorder()
	h.HandleSession(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestHandleStop_UnknownIDStill409(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	body := mustJSON(t, map[string]string{"id": "missing-run"})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/stop", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleStop(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeSessionNotFound {
		t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeSessionNotFound)
	}
}

func TestMountPlaneARoutes_SessionSuffixExtraNotRouted(t *testing.T) {
	t.Parallel()

	r := newPlaneATestRouter(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/run-1/extra", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for suffix path", rec.Code)
	}
}
