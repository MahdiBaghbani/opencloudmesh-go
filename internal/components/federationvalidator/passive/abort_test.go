// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

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
