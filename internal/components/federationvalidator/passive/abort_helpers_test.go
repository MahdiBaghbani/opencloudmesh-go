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

func abortRouter(h *Handler) chi.Router {
	r := chi.NewRouter()
	abort := AbortSessionRouteSpec()
	r.Method(abort.Method, abort.Pattern, http.HandlerFunc(h.HandleAbort))

	return r
}

func postAbort(t *testing.T, h *Handler, runID string, body []byte) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/session/"+runID+"/abort", reader)
	rec := httptest.NewRecorder()
	abortRouter(h).ServeHTTP(rec, req)

	return rec
}

func seedAbortRun(t *testing.T, store *validatorcore.Core, runID string, active bool, state string) {
	t.Helper()

	now := time.Now().Unix()
	if err := store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:  runID,
		IsActive:   active,
		State:      state,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func decodeAbortError(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	return payload
}

func decodeAbortOK(t *testing.T, rec *httptest.ResponseRecorder, runID string) abortResponse {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body %s", rec.Code, rec.Body.String())
	}

	var payload abortResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload.ID != runID || payload.State != validatorcore.StateTerminalFail {
		t.Fatalf("response = %+v, want id=%q state=%q", payload, runID, validatorcore.StateTerminalFail)
	}

	return payload
}

func loadAbortRun(t *testing.T, store *validatorcore.Core, runID string) *validatorcore.TestRun {
	t.Helper()

	got, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	return got
}

func assertPersistedOperatorAbort(t *testing.T, got *validatorcore.TestRun) {
	t.Helper()

	if got.IsActive {
		t.Fatal("is_active = 1, want 0")
	}

	if got.State != validatorcore.StateTerminalFail {
		t.Fatalf("persisted state = %q, want %q", got.State, validatorcore.StateTerminalFail)
	}

	if got.TerminalReason == nil || *got.TerminalReason != validatorcore.ReasonOperatorAborted {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, validatorcore.ReasonOperatorAborted)
	}

	if got.OverallGrade == nil || *got.OverallGrade != validatorcore.GradeFail {
		t.Fatalf("overall_grade = %v, want %q", got.OverallGrade, validatorcore.GradeFail)
	}
}

func assertAbortUnflippable(t *testing.T, store *validatorcore.Core, runID string) {
	t.Helper()

	passed, err := store.FlipLateReverseShareToPass(t.Context(), runID)
	if err != nil {
		t.Fatalf("FlipLateReverseShareToPass: %v", err)
	}

	if passed {
		t.Fatal("late flip returned true, want the hard-fail row to stay closed")
	}

	after := loadAbortRun(t, store, runID)
	if after.State != validatorcore.StateTerminalFail {
		t.Fatalf("state after flip = %q, want %q", after.State, validatorcore.StateTerminalFail)
	}

	if after.TerminalReason == nil || *after.TerminalReason != validatorcore.ReasonOperatorAborted {
		t.Fatalf("terminal_reason after flip = %v, want unchanged", after.TerminalReason)
	}
}

func assertAbortConflict(t *testing.T, rec *httptest.ResponseRecorder, code string) {
	t.Helper()

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 body %s", rec.Code, rec.Body.String())
	}

	payload := decodeAbortError(t, rec)
	if payload["error"] != code {
		t.Fatalf("error = %q, want %q", payload["error"], code)
	}
}
