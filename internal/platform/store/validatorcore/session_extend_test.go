// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"
	"time"
)

func TestExtendToActive_RequiresPassiveComplete(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-extend-not-ready"

	row := &TestRun{
		TestRunID:   runID,
		State:       StateCreated,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "extend.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	err := core.ExtendToActive(ctx, runID)
	if !errors.Is(err, ErrSessionNotReady) {
		t.Fatalf("ExtendToActive error = %v, want ErrSessionNotReady", err)
	}
}

func TestExtendToActive_ConflictsWithOneActiveLock(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()

	for _, id := range []string{"run-active-a", "run-active-b"} {
		row := &TestRun{
			TestRunID:   id,
			State:       StatePassiveComplete,
			SessionKind: SessionKindPassiveOnly,
			TargetHost:  "lock.example",
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	if err := core.ExtendToActive(ctx, "run-active-a"); err != nil {
		t.Fatalf("first extend: %v", err)
	}

	extendErr := core.ExtendToActive(ctx, "run-active-b")

	var storeErr *StoreError
	if !errors.As(extendErr, &storeErr) || storeErr.Op != OpExtendUpdate {
		t.Fatalf("second extend error = %v, want OpExtendUpdate store error", extendErr)
	}
}

func TestExtendToActive_TerminalStateReturnsSessionNotReady(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-extend-terminal"

	row := &TestRun{
		TestRunID:   runID,
		State:       StateTerminalPass,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "terminal.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	err := core.ExtendToActive(ctx, runID)
	if !errors.Is(err, ErrSessionNotReady) {
		t.Fatalf("ExtendToActive error = %v, want ErrSessionNotReady", err)
	}

	if errors.Is(err, ErrStopSessionMiss) {
		t.Fatalf("ExtendToActive must not return ErrStopSessionMiss for terminal state")
	}
}

func TestExtendToActive_RepeatedExtensionReturnsInteractiveConflict(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-repeat-extend"

	row := &TestRun{
		TestRunID:   runID,
		State:       StatePassiveComplete,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "repeat.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := core.ExtendToActive(ctx, runID); err != nil {
		t.Fatalf("first extend: %v", err)
	}

	err := core.ExtendToActive(ctx, runID)
	if !errors.Is(err, ErrInteractiveRunInProgress) {
		t.Fatalf("repeat extend error = %v, want ErrInteractiveRunInProgress", err)
	}
}

func TestExtendToActive_WritesBobUserIDOnPromotion(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-extend-bob"

	row := &TestRun{
		TestRunID:   runID,
		State:       StatePassiveComplete,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "bob.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := core.ExtendToActive(ctx, runID); err != nil {
		t.Fatalf("ExtendToActive: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive {
		t.Fatal("is_active = 0, want 1")
	}

	if got.State != StateActiveRunning {
		t.Fatalf("state = %q, want %q", got.State, StateActiveRunning)
	}

	if got.BobUserID == nil || *got.BobUserID == "" {
		t.Fatal("bob_user_id must be written in the extend transaction")
	}
}

func TestExtendToActive_ConflictLeavesBobUserIDUnset(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()

	for _, id := range []string{"run-bob-a", "run-bob-b"} {
		row := &TestRun{
			TestRunID:   id,
			State:       StatePassiveComplete,
			SessionKind: SessionKindPassiveOnly,
			TargetHost:  "lock.example",
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	if err := core.ExtendToActive(ctx, "run-bob-a"); err != nil {
		t.Fatalf("first extend: %v", err)
	}

	if err := core.ExtendToActive(ctx, "run-bob-b"); err == nil {
		t.Fatal("second extend succeeded, want conflict")
	}

	lost, err := core.GetTestRun(ctx, "run-bob-b")
	if err != nil {
		t.Fatalf("GetTestRun run-bob-b: %v", err)
	}

	if lost.IsActive {
		t.Fatal("conflicted row must stay inactive")
	}

	if lost.BobUserID != nil {
		t.Fatalf("conflicted row bob_user_id = %v, want unset", lost.BobUserID)
	}
}
