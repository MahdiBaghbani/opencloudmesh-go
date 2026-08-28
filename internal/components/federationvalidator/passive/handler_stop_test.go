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

func TestHandleStop_SessionNotReady(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()

	runID := "run-not-ready"
	row := &validatorcore.TestRun{
		TestRunID:  runID,
		State:      validatorcore.StateCreated,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := store.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := mustJSON(t, map[string]string{"id": runID})

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

	if payload["error"] != validatorcore.CodeSessionNotReady {
		t.Fatalf("error code = %q, want %q", payload["error"], validatorcore.CodeSessionNotReady)
	}
}

func TestHandleStop_ActivePassiveCompleteReturnsSessionNotReady(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()

	runID := "run-active-pc-stop"
	row := &validatorcore.TestRun{
		TestRunID:  runID,
		IsActive:   true,
		State:      validatorcore.StatePassiveComplete,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := store.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := mustJSON(t, map[string]string{"id": runID})

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

	if payload["error"] != validatorcore.CodeSessionNotReady {
		t.Fatalf("error code = %q, want %q", payload["error"], validatorcore.CodeSessionNotReady)
	}

	if payload["error"] == validatorcore.CodeInteractiveRunInProgress {
		t.Fatalf("stop on active passive_complete must not return %q", validatorcore.CodeInteractiveRunInProgress)
	}
}
