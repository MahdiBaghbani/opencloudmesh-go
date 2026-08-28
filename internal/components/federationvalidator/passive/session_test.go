// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

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
