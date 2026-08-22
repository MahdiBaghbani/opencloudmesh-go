// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestHandleAbort_ActiveRunWritesTerminalFail(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-http-abort-active"

	seedAbortRun(t, store, runID, true, validatorcore.StateActiveRunning)

	payload := decodeAbortOK(t, postAbort(t, h, runID, nil), runID)
	got := loadAbortRun(t, store, runID)
	assertPersistedOperatorAbort(t, got)

	if payload.State != got.State {
		t.Fatalf("response state %q != persisted %q", payload.State, got.State)
	}

	assertAbortUnflippable(t, store, runID)
}

func TestHandleAbort_InactiveReturnsSessionNotReady(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state string
	}{
		{name: "created", state: validatorcore.StateCreated},
		{name: "passive complete", state: validatorcore.StatePassiveComplete},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := openHandlerTestStore(t)
			h := NewHandler(store, nil)
			runID := "run-http-abort-inactive-" + strings.ReplaceAll(tt.state, "_", "-")

			seedAbortRun(t, store, runID, false, tt.state)

			rec := postAbort(t, h, runID, nil)
			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409 body %s", rec.Code, rec.Body.String())
			}

			payload := decodeAbortError(t, rec)
			if payload["error"] != validatorcore.CodeSessionNotReady {
				t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeSessionNotReady)
			}

			got, err := store.GetTestRun(t.Context(), runID)
			if err != nil {
				t.Fatalf("GetTestRun: %v", err)
			}

			if got.IsActive || got.State != tt.state {
				t.Fatalf("is_active=%v state=%q, want inactive %q", got.IsActive, got.State, tt.state)
			}
		})
	}
}

func TestHandleAbort_GradedExerciseRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state string
	}{
		{name: "capability exercise", state: validatorcore.StateCapabilityExercise},
		{name: "reverse awaiting share", state: validatorcore.StateReverseAwaitingShare},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := openHandlerTestStore(t)
			h := NewHandler(store, nil)
			runID := "run-http-abort-refused-" + strings.ReplaceAll(tt.state, "_", "-")

			seedAbortRun(t, store, runID, true, tt.state)

			rec := postAbort(t, h, runID, nil)
			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409 body %s", rec.Code, rec.Body.String())
			}

			payload := decodeAbortError(t, rec)
			if payload["error"] != validatorcore.CodeAbortRefused {
				t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeAbortRefused)
			}

			got, err := store.GetTestRun(t.Context(), runID)
			if err != nil {
				t.Fatalf("GetTestRun: %v", err)
			}

			if !got.IsActive || got.State != tt.state {
				t.Fatalf("is_active=%v state=%q, want active %q", got.IsActive, got.State, tt.state)
			}
		})
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

func TestHandleAbort_SecondAbortMiss(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-http-abort-twice"

	seedAbortRun(t, store, runID, true, validatorcore.StateInviteMinted)
	decodeAbortOK(t, postAbort(t, h, runID, nil), runID)
	assertAbortConflict(t, postAbort(t, h, runID, nil), validatorcore.CodeAbortSessionMiss)
	assertPersistedOperatorAbort(t, loadAbortRun(t, store, runID))
}

func TestHandleAbort_AlreadyTerminalMiss(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-http-abort-terminal"
	reason := "already-closed"
	grade := validatorcore.GradePass
	now := time.Now().Unix()

	if err := store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		TargetHost:     "peer.example",
		TerminalReason: &reason,
		OverallGrade:   &grade,
		FinishedAt:     &now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	assertAbortConflict(t, postAbort(t, h, runID, nil), validatorcore.CodeAbortSessionMiss)

	got := loadAbortRun(t, store, runID)
	if got.IsActive || got.State != validatorcore.StateTerminalPass {
		t.Fatalf("is_active=%v state=%q, want untouched terminal_pass", got.IsActive, got.State)
	}

	if got.TerminalReason == nil || *got.TerminalReason != reason {
		t.Fatalf("terminal_reason = %v, want unchanged %q", got.TerminalReason, reason)
	}
}

func TestHandleAbort_HybridActiveTerminalMiss(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-http-abort-hybrid"
	reason := "completed"
	now := time.Now().Unix()

	if err := store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:      runID,
		IsActive:       true,
		State:          validatorcore.StateTerminalPass,
		TargetHost:     "peer.example",
		TerminalReason: &reason,
		FinishedAt:     &now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	assertAbortConflict(t, postAbort(t, h, runID, nil), validatorcore.CodeAbortSessionMiss)

	got := loadAbortRun(t, store, runID)
	if !got.IsActive || got.State != validatorcore.StateTerminalPass {
		t.Fatalf("is_active=%v state=%q, want untouched hybrid terminal_pass", got.IsActive, got.State)
	}
}

func TestHandleAbort_UnknownID404(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	rec := postAbort(t, h, "missing-run", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 body %s", rec.Code, rec.Body.String())
	}

	payload := decodeAbortError(t, rec)
	if payload["error"] != validatorcore.CodeSessionNotFound {
		t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeSessionNotFound)
	}
}

func TestHandleAbort_InvalidJSONBodyUsesURLID(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-http-abort-body"

	seedAbortRun(t, store, runID, true, validatorcore.StateForwardShareSent)
	decodeAbortOK(t, postAbort(t, h, runID, []byte("{not-json")), runID)
	assertPersistedOperatorAbort(t, loadAbortRun(t, store, runID))
}

func TestHandleAbort_DirectGETMethodNotAllowed(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/run-1/abort", nil)
	rec := httptest.NewRecorder()
	h.HandleAbort(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestHandleAbort_MountedGETAndSuffix(t *testing.T) {
	t.Parallel()

	r := newPlaneATestRouter(t)

	getReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/run-1/abort", nil)
	getRec := httptest.NewRecorder()
	r.ServeHTTP(getRec, getReq)

	if getRec.Code == http.StatusOK {
		t.Fatal("mounted GET abort must not succeed")
	}

	extraReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/session/run-1/abort/extra", nil)
	extraRec := httptest.NewRecorder()
	r.ServeHTTP(extraRec, extraReq)

	if extraRec.Code != http.StatusNotFound {
		t.Fatalf("suffix status = %d, want 404", extraRec.Code)
	}
}

func TestHandleAbort_ConcurrentSecondMissDoesNotRewrite(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-http-abort-race"

	seedAbortRun(t, store, runID, true, validatorcore.StateActiveRunning)

	results := make([]*httptest.ResponseRecorder, 2)

	var wg sync.WaitGroup

	for i := range results {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			results[i] = postAbort(t, h, runID, nil)
		}(i)
	}

	wg.Wait()

	var okCount, missCount int

	for _, rec := range results {
		switch rec.Code {
		case http.StatusOK:
			okCount++
		case http.StatusConflict:
			missCount++

			payload := decodeAbortError(t, rec)
			if payload["error"] != validatorcore.CodeAbortSessionMiss {
				t.Fatalf("raced miss error = %q, want %q", payload["error"], validatorcore.CodeAbortSessionMiss)
			}
		case http.StatusGone:
			t.Fatal("raced abort must not return 410")
		default:
			t.Fatalf("raced status = %d body %s", rec.Code, rec.Body.String())
		}
	}

	if okCount != 1 || missCount != 1 {
		t.Fatalf("raced outcomes ok=%d miss=%d, want 1 and 1", okCount, missCount)
	}

	got, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive || got.State != validatorcore.StateTerminalFail {
		t.Fatalf("is_active=%v state=%q, want one terminal_fail write", got.IsActive, got.State)
	}

	if got.TerminalReason == nil || *got.TerminalReason != validatorcore.ReasonOperatorAborted {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, validatorcore.ReasonOperatorAborted)
	}
}

func TestMountPlaneARoutes_AbortIsPostOnly(t *testing.T) {
	t.Parallel()

	r := newPlaneATestRouter(t)

	routes, err := EnumeratePlaneARoutes(r)
	if err != nil {
		t.Fatalf("EnumeratePlaneARoutes: %v", err)
	}

	var abortPosts, abortGets int

	for _, route := range routes {
		if !strings.HasSuffix(route.FullPath, "/api/session/{id}/abort") {
			continue
		}

		switch route.Method {
		case http.MethodPost:
			abortPosts++
		case http.MethodGet:
			abortGets++
		}
	}

	if abortPosts != 1 {
		t.Fatalf("POST abort routes = %d, want 1", abortPosts)
	}

	if abortGets != 0 {
		t.Fatalf("GET abort routes = %d, want 0", abortGets)
	}
}

func TestAbortSource_UsesHardFailWriter(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("abort.go")
	if err != nil {
		t.Fatalf("read abort.go: %v", err)
	}

	text := string(src)
	if !strings.Contains(text, "ReleaseActiveHardFail") {
		t.Fatal("abort handler must call ReleaseActiveHardFail")
	}

	if !strings.Contains(text, "ReasonOperatorAborted") {
		t.Fatal("abort handler must pass ReasonOperatorAborted")
	}

	for _, banned := range []string{
		"StateInterrupted",
		"FlipLateReverseShareToPass",
		"ReasonReverseShareTimeout",
		"interrupted",
	} {
		if strings.Contains(text, banned) {
			t.Fatalf("abort.go must not mention %q", banned)
		}
	}
}

func TestOperatorAborted_NotUsedByActiveRunner(t *testing.T) {
	t.Parallel()

	err := filepath.WalkDir("../active", func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		data, readErr := os.ReadFile(path) //nolint:gosec // test walks the local active tree
		if readErr != nil {
			return fmt.Errorf("read %s: %w", path, readErr)
		}

		if bytes.Contains(data, []byte("operator_aborted")) ||
			bytes.Contains(data, []byte("ReasonOperatorAborted")) {
			t.Errorf("%s uses operator abort reason", path)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk active tree: %v", err)
	}
}
