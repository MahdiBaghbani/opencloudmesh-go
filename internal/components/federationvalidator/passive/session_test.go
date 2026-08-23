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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
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

func TestHandleSession_ReturnsStateTsAndNextInstruction(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	now := time.Now().Unix()
	runID := "run-poll"

	seedSessionRow(t, store, &validatorcore.TestRun{
		TestRunID:  runID,
		State:      validatorcore.StatePassiveRunning,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now + 42,
	})

	payload := pollSession(t, h, runID)

	assertExactKeys(t, payload, []string{"state", "ts", "nextInstruction"})

	var state string
	if err := json.Unmarshal(payload["state"], &state); err != nil {
		t.Fatalf("state: %v", err)
	}

	if state != validatorcore.StatePassiveRunning {
		t.Fatalf("state = %q, want %q", state, validatorcore.StatePassiveRunning)
	}

	var ts int64
	if err := json.Unmarshal(payload["ts"], &ts); err != nil {
		t.Fatalf("ts: %v", err)
	}

	if ts != now+42 {
		t.Fatalf("ts = %d, want %d", ts, now+42)
	}

	if next := pollNextInstruction(t, payload); next != "wait_probe" {
		t.Fatalf("nextInstruction = %q, want %q", next, "wait_probe")
	}
}

func TestHandleSession_NextInstructionPerState(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		state    string
		isActive bool
		want     string
	}{
		{name: "created", state: validatorcore.StateCreated, want: "wait_probe"},
		{name: "passive_running", state: validatorcore.StatePassiveRunning, want: "wait_probe"},
		{name: "passive_complete", state: validatorcore.StatePassiveComplete, want: "stop"},
		{name: "active_running", state: validatorcore.StateActiveRunning, isActive: true, want: "wait_invite_mint"},
		{name: "invite_minted", state: validatorcore.StateInviteMinted, isActive: true, want: "paste_s1"},
		{name: "invite_accepted", state: validatorcore.StateInviteAccepted, isActive: true, want: "wait_reverse_start"},
		{name: "reverse_awaiting_invite", state: validatorcore.StateReverseAwaitingInvite, isActive: true, want: "paste_s2"},
		{name: "reverse_invite_accepted", state: validatorcore.StateReverseInviteAccepted, isActive: true, want: "wait_forward_share"},
		{name: "forward_share_sent", state: validatorcore.StateForwardShareSent, isActive: true, want: "open_forward_file"},
		{name: "capability_exercise", state: validatorcore.StateCapabilityExercise, isActive: true, want: "wait_oq2_open"},
		{name: "reverse_awaiting_share", state: validatorcore.StateReverseAwaitingShare, isActive: true, want: "wait_reverse_share_or_timeout"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := openHandlerTestStore(t)
			h := NewHandler(store, nil)
			now := time.Now().Unix()
			runID := "run-" + tc.name

			seedSessionRow(t, store, &validatorcore.TestRun{
				TestRunID:  runID,
				IsActive:   tc.isActive,
				State:      tc.state,
				TargetHost: "peer.example",
				CreatedAt:  now,
				UpdatedAt:  now,
			})

			payload := pollSession(t, h, runID)

			assertExactKeys(t, payload, []string{"state", "ts", "nextInstruction"})

			if next := pollNextInstruction(t, payload); next != tc.want {
				t.Fatalf("nextInstruction = %q, want %q", next, tc.want)
			}
		})
	}
}

func TestHandleSession_PassiveCompletePublishesStop(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	now := time.Now().Unix()
	runID := "run-complete-stop"

	seedSessionRow(t, store, &validatorcore.TestRun{
		TestRunID:   runID,
		State:       validatorcore.StatePassiveComplete,
		TargetHost:  "peer.example",
		OptInActive: false,
		CreatedAt:   now,
		UpdatedAt:   now,
	})

	payload := pollSession(t, h, runID)

	assertExactKeys(t, payload, []string{"state", "ts", "nextInstruction"})

	if next := pollNextInstruction(t, payload); next != "stop" {
		t.Fatalf("nextInstruction = %q, want %q", next, "stop")
	}
}

func TestHandleSession_PassiveCompleteOptInActiveUnreachable(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	now := time.Now().Unix()

	err := store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:   "run-complete-opt-in",
		State:       validatorcore.StatePassiveComplete,
		TargetHost:  "peer.example",
		OptInActive: true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}).Error
	if err == nil {
		t.Fatal("passive_complete with opt_in_active=1 must be rejected")
	}
}

func TestHandleSession_ReadyWaiterPublishesActiveSlot(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	now := time.Now().Unix()
	runID := "run-poll-waiter"
	readyAt := now - 5

	if err := store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:  "run-poll-holder",
		IsActive:   true,
		State:      validatorcore.StateActiveRunning,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}).Error; err != nil {
		t.Fatalf("seed holder: %v", err)
	}

	seedSessionRow(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StatePassiveRunning,
		TargetHost:     "peer.example",
		OptInActive:    true,
		PassiveReadyAt: &readyAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	})

	payload := pollSession(t, h, runID)

	assertExactKeys(t, payload, []string{"state", "ts", "nextInstruction"})

	if next := pollNextInstruction(t, payload); next != "wait_active_slot" {
		t.Fatalf("nextInstruction = %q, want wait_active_slot", next)
	}

	got, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive || got.State != validatorcore.StatePassiveRunning {
		t.Fatalf("lock-held waiter is_active=%v state=%q", got.IsActive, got.State)
	}
}

func TestHandleSession_EmptyCapsDoesNotPromoteReadyWaiter(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	h.SetCaps(catalog.Caps{})

	now := time.Now().Unix()
	runID := "run-poll-no-extend"
	readyAt := now - 5

	seedSessionRow(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StatePassiveRunning,
		TargetHost:     "peer.example",
		OptInActive:    true,
		PassiveReadyAt: &readyAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	})

	payload := pollSession(t, h, runID)

	if next := pollNextInstruction(t, payload); next != "wait_active_slot" {
		t.Fatalf("nextInstruction = %q, want wait_active_slot", next)
	}

	got, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive || got.State != validatorcore.StatePassiveRunning {
		t.Fatalf("empty caps promoted session: is_active=%v state=%q", got.IsActive, got.State)
	}
}

func TestHandleSession_FullCapsPromotesReadyWaiter(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	h.SetCaps(catalog.FullCaps())

	now := time.Now().Unix()
	runID := "run-poll-full-extend"
	readyAt := now - 5

	seedSessionRow(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StatePassiveRunning,
		TargetHost:     "peer.example",
		OptInActive:    true,
		PassiveReadyAt: &readyAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	})

	payload := pollSession(t, h, runID)

	if next := pollNextInstruction(t, payload); next != "wait_invite_mint" {
		t.Fatalf("nextInstruction = %q, want wait_invite_mint", next)
	}

	got, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive || got.State != validatorcore.StateActiveRunning {
		t.Fatalf("is_active=%v state=%q, want active_running", got.IsActive, got.State)
	}
}

func TestHandleSession_ReadyWaiterPromotesWhenSlotFree(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	allowActiveExtend(h)

	now := time.Now().Unix()
	runID := "run-poll-promote"
	readyAt := now - 5

	seedSessionRow(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StatePassiveRunning,
		TargetHost:     "peer.example",
		OptInActive:    true,
		PassiveReadyAt: &readyAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	})

	payload := pollSession(t, h, runID)

	if next := pollNextInstruction(t, payload); next != "wait_invite_mint" {
		t.Fatalf("nextInstruction = %q, want wait_invite_mint", next)
	}

	got, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive || got.State != validatorcore.StateActiveRunning {
		t.Fatalf("is_active=%v state=%q, want active_running", got.IsActive, got.State)
	}
}

func TestHandleSession_TerminalStatesOmitNextInstruction(t *testing.T) {
	t.Parallel()

	for _, state := range []string{
		validatorcore.StateTerminalPass,
		validatorcore.StateTerminalFail,
		validatorcore.StateInterrupted,
	} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()

			store := openHandlerTestStore(t)
			h := NewHandler(store, nil)
			now := time.Now().Unix()
			finishedAt := now + 1
			runID := "run-" + state

			seedSessionRow(t, store, &validatorcore.TestRun{
				TestRunID:  runID,
				State:      state,
				TargetHost: "peer.example",
				FinishedAt: &finishedAt,
				CreatedAt:  now,
				UpdatedAt:  finishedAt,
			})

			payload := pollSession(t, h, runID)

			assertExactKeys(t, payload, []string{"state", "ts"})
		})
	}
}

func TestHandleSession_PollDoesNotMutateSession(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-readonly"

	seedSessionRow(t, store, &validatorcore.TestRun{
		TestRunID:  runID,
		State:      validatorcore.StatePassiveComplete,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now + 7,
	})

	before, err := store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("load before poll: %v", err)
	}

	pollSession(t, h, runID)

	after, err := store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("load after poll: %v", err)
	}

	if !reflect.DeepEqual(before, after) {
		t.Fatalf("poll mutated session row: before %+v, after %+v", before, after)
	}
}

func TestHandleSession_PollOmitsSensitiveSessionFields(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	now := time.Now().Unix()
	runID := "run-secrets"

	bobUserID := "probe-user-id-marker"
	reverseInvite := "reverse-invite-string-marker"
	designatedShareWith := "validator-party-email@example.com"
	reverseShareProviderID := "bob-cloudid-marker"

	seedSessionRow(t, store, &validatorcore.TestRun{
		TestRunID:              runID,
		IsActive:               true,
		State:                  validatorcore.StateReverseAwaitingInvite,
		TargetHost:             "peer.example",
		BobUserID:              &bobUserID,
		ReverseInviteToken:     &reverseInvite,
		DesignatedShareWith:    &designatedShareWith,
		ReverseShareProviderID: &reverseShareProviderID,
		CreatedAt:              now,
		UpdatedAt:              now,
	})

	rec := doPoll(t, h, runID)
	body := rec.Body.String()

	for _, secret := range []string{bobUserID, reverseInvite, designatedShareWith, reverseShareProviderID} {
		if strings.Contains(body, secret) {
			t.Fatalf("poll response leaks %q: %s", secret, body)
		}
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	assertExactKeys(t, payload, []string{"state", "ts", "nextInstruction"})

	if next := pollNextInstruction(t, payload); next != "paste_s2" {
		t.Fatalf("nextInstruction = %q, want %q", next, "paste_s2")
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
