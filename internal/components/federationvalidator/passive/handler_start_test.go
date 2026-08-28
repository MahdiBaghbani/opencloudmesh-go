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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestHandleStart_RejectsDualFieldBody(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	body := mustJSON(t, map[string]string{
		"target": "https://peer.example",
		"id":     "run-1",
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.HandleStart(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHandleStart_CreateThenStop(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()

	runID := "run-stop-flow"
	row := &validatorcore.TestRun{
		TestRunID:  runID,
		State:      validatorcore.StatePassiveComplete,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := store.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed passive_complete: %v", err)
	}

	stopBody := mustJSON(t, map[string]string{"id": runID})

	stopReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/stop", bytes.NewReader(stopBody))
	stopRec := httptest.NewRecorder()
	h.HandleStop(stopRec, stopReq)

	if stopRec.Code != http.StatusOK {
		t.Fatalf("stop status = %d, want 200", stopRec.Code)
	}
}

func TestHandleStart_CreateSessionReturnsID(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	createBody := mustJSON(t, map[string]string{"target": "https://peer.example"})

	createReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(createBody))
	createRec := httptest.NewRecorder()
	h.HandleStart(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", createRec.Code)
	}

	var created startCreateResponse
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	if created.ID == "" {
		t.Fatal("expected non-empty session id")
	}
}

func TestHandleStart_IDOnlyIsRejected(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	body := mustJSON(t, map[string]string{"id": "run-old-extend"})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleStart(rec, req)

	assertJSONError(t, rec, "invalid_request")
}

func TestCreateSessionRouteSpec_IncludesStop(t *testing.T) {
	t.Parallel()

	stop := StopSessionRouteSpec()
	if stop.Pattern != RouteStopSession {
		t.Fatalf("stop pattern = %q, want %q", stop.Pattern, RouteStopSession)
	}
}

func TestHandleStart_DoesNotOptInStatistics(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()

	createBody := mustJSON(t, map[string]string{"target": "https://peer.example"})

	createReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(createBody))
	createRec := httptest.NewRecorder()
	h.HandleStart(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", createRec.Code)
	}

	var created startCreateResponse
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	waitForState(t, store, ctx, created.ID)

	stopBody := mustJSON(t, map[string]string{"id": created.ID})

	stopReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/stop", bytes.NewReader(stopBody))
	stopRec := httptest.NewRecorder()
	h.HandleStop(stopRec, stopReq)

	if stopRec.Code != http.StatusOK {
		t.Fatalf("stop status = %d, want 200", stopRec.Code)
	}

	var rawCount int64
	if err := store.DB().WithContext(ctx).Model(&validatorcore.StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 0 {
		t.Fatalf("stats_raw count = %d, want 0 for POST /start default incognito", rawCount)
	}
}
