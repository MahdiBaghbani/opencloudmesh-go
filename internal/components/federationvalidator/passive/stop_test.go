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

func TestHandleStop_ReturnsReloadedPersistedState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		runID     string
		area      string
		severity  string
		wantState string
	}{
		{
			name:      "pass without evidence",
			runID:     "run-http-stop-pass",
			wantState: validatorcore.StateTerminalPass,
		},
		{
			name:      "warn still passes",
			runID:     "run-http-stop-warn",
			area:      validatorcore.SpecificationAreaDiscovery,
			severity:  validatorcore.GradeWarn,
			wantState: validatorcore.StateTerminalPass,
		},
		{
			name:      "failed discovery cannot pass",
			runID:     "run-http-stop-discovery-fail",
			area:      validatorcore.SpecificationAreaDiscovery,
			severity:  validatorcore.GradeFail,
			wantState: validatorcore.StateTerminalFail,
		},
		{
			name:      "failed tls cannot pass",
			runID:     "run-http-stop-tls-fail",
			area:      validatorcore.SpecificationAreaTLS,
			severity:  validatorcore.GradeFail,
			wantState: validatorcore.StateTerminalFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := openHandlerTestStore(t)
			h := NewHandler(store, nil)
			ctx := t.Context()
			now := time.Now().Unix()

			if err := store.DB().WithContext(ctx).Create(&validatorcore.TestRun{
				TestRunID:  tt.runID,
				State:      validatorcore.StatePassiveComplete,
				TargetHost: "peer.example",
				CreatedAt:  now,
				UpdatedAt:  now,
			}).Error; err != nil {
				t.Fatalf("seed: %v", err)
			}

			if tt.area != "" {
				if err := store.ApplyEvidenceFact(ctx, validatorcore.ApplyEvidenceFactInput{
					TestRunID:    tt.runID,
					Area:         tt.area,
					Step:         "probe",
					ReasonCode:   "probed",
					Severity:     tt.severity,
					AffectsGrade: true,
					Leg:          validatorcore.EvidenceLegPassive,
				}); err != nil {
					t.Fatalf("ApplyEvidenceFact: %v", err)
				}
			}

			rec := postStop(t, h, tt.runID)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 body %s", rec.Code, rec.Body.String())
			}

			var payload stopResponse
			if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
				t.Fatalf("decode: %v", err)
			}

			if payload.State != tt.wantState {
				t.Fatalf("response state = %q, want %q", payload.State, tt.wantState)
			}

			got, err := store.GetTestRun(ctx, tt.runID)
			if err != nil {
				t.Fatalf("GetTestRun: %v", err)
			}

			if payload.State != got.State {
				t.Fatalf("response state %q != persisted %q", payload.State, got.State)
			}
		})
	}
}

func TestHandleStop_AlreadyTerminalReturnsPersistedState(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-http-stop-terminal"
	reason := "already-terminal"
	grade := validatorcore.GradeFail

	if err := store.DB().WithContext(ctx).Create(&validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalFail,
		TargetHost:     "peer.example",
		TerminalReason: &reason,
		OverallGrade:   &grade,
		FinishedAt:     &now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	first := postStop(t, h, runID)
	if first.Code != http.StatusOK {
		t.Fatalf("first stop status = %d, want 200 body %s", first.Code, first.Body.String())
	}

	var firstPayload stopResponse
	if err := json.NewDecoder(first.Body).Decode(&firstPayload); err != nil {
		t.Fatalf("decode first: %v", err)
	}

	if firstPayload.State != validatorcore.StateTerminalFail {
		t.Fatalf("first state = %q, want %q", firstPayload.State, validatorcore.StateTerminalFail)
	}

	second := postStop(t, h, runID)
	if second.Code != http.StatusOK {
		t.Fatalf("second stop status = %d, want 200 body %s", second.Code, second.Body.String())
	}

	var secondPayload stopResponse
	if err := json.NewDecoder(second.Body).Decode(&secondPayload); err != nil {
		t.Fatalf("decode second: %v", err)
	}

	if secondPayload.State != validatorcore.StateTerminalFail {
		t.Fatalf("second state = %q, want persisted terminal_fail", secondPayload.State)
	}
}

func TestHandleStop_SecondStopOnJustTerminalizedRun(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-http-stop-twice"

	if err := store.DB().WithContext(ctx).Create(&validatorcore.TestRun{
		TestRunID:  runID,
		State:      validatorcore.StatePassiveComplete,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	first := postStop(t, h, runID)
	if first.Code != http.StatusOK {
		t.Fatalf("first stop status = %d, want 200", first.Code)
	}

	second := postStop(t, h, runID)
	if second.Code != http.StatusOK {
		t.Fatalf("second stop status = %d, want 200 body %s", second.Code, second.Body.String())
	}

	var payload stopResponse
	if err := json.NewDecoder(second.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	got, err := store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if payload.State != got.State {
		t.Fatalf("response state %q != persisted %q", payload.State, got.State)
	}

	if payload.State != validatorcore.StateTerminalPass {
		t.Fatalf("state = %q, want %q", payload.State, validatorcore.StateTerminalPass)
	}
}

func TestHandleStop_AbandonsReadyWaiter(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-http-stop-waiter"
	readyAt := now - 3

	if err := store.DB().WithContext(ctx).Create(&validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StatePassiveRunning,
		TargetHost:     "peer.example",
		OptInActive:    true,
		PassiveReadyAt: &readyAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := postStop(t, h, runID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body %s", rec.Code, rec.Body.String())
	}

	var payload stopResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload.State != validatorcore.StateTerminalFail {
		t.Fatalf("response state = %q, want %q", payload.State, validatorcore.StateTerminalFail)
	}

	got, err := store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.TerminalReason == nil || *got.TerminalReason != validatorcore.ReasonOperatorAborted {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, validatorcore.ReasonOperatorAborted)
	}
}

func postStop(t *testing.T, h *Handler, runID string) *httptest.ResponseRecorder {
	t.Helper()

	body := mustJSON(t, map[string]string{"id": runID})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/stop", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleStop(rec, req)

	return rec
}
