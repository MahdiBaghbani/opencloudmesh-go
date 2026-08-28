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
		TestRunID:  runID,
		State:      StateCreated,
		TargetHost: "extend.example",
		CreatedAt:  now,
		UpdatedAt:  now,
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
			TestRunID:  id,
			State:      StatePassiveComplete,
			TargetHost: "lock.example",
			CreatedAt:  now,
			UpdatedAt:  now,
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
		TestRunID:  runID,
		State:      StateTerminalPass,
		TargetHost: "terminal.example",
		CreatedAt:  now,
		UpdatedAt:  now,
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

func TestExtendToActive_RepeatedExtensionIsIdempotent(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-repeat-extend"

	row := &TestRun{
		TestRunID:  runID,
		State:      StatePassiveComplete,
		TargetHost: "repeat.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := core.ExtendToActive(ctx, runID); err != nil {
		t.Fatalf("first extend: %v", err)
	}

	if err := core.ExtendToActive(ctx, runID); err != nil {
		t.Fatalf("repeat extend: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive || got.State != StateActiveRunning {
		t.Fatalf("repeat extend is_active=%v state=%q", got.IsActive, got.State)
	}
}

func TestExtendToActive_PromotesPassiveRunningOptIn(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-extend-running"

	seedPassiveRunningOptIn(t, core, runID)

	if err := core.ExtendToActive(ctx, runID); err != nil {
		t.Fatalf("ExtendToActive: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive || got.State != StateActiveRunning {
		t.Fatalf("is_active=%v state=%q, want active_running", got.IsActive, got.State)
	}

	if got.BobUserID == nil || *got.BobUserID == "" {
		t.Fatal("bob_user_id must be minted on running promotion")
	}

	if SessionKindOf(got) != SessionKindActiveFull {
		t.Fatalf("session kind = %q, want %q", SessionKindOf(got), SessionKindActiveFull)
	}
}

func TestExtendToActive_OptOutRunningStaysNotReady(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-extend-opt-out-running"

	row := &TestRun{
		TestRunID:  runID,
		State:      StatePassiveRunning,
		TargetHost: "running.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	err := core.ExtendToActive(ctx, runID)
	if !errors.Is(err, ErrSessionNotReady) {
		t.Fatalf("ExtendToActive error = %v, want ErrSessionNotReady", err)
	}
}

func TestExtendToActive_RefusesPersistedDiscoveryFail(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-extend-fail-gate"

	seedPassiveComplete(t, core, runID, "https://peer.example", false)
	seedGradedEvidence(t, core, runID, SpecificationAreaDiscovery, GradeFail)

	err := core.ExtendToActive(ctx, runID)
	if !errors.Is(err, ErrSessionNotReady) {
		t.Fatalf("ExtendToActive error = %v, want ErrSessionNotReady", err)
	}

	got, getErr := core.GetTestRun(ctx, runID)
	if getErr != nil {
		t.Fatalf("GetTestRun: %v", getErr)
	}

	if got.IsActive {
		t.Fatal("failed-probe run must not take the active lock")
	}

	if got.State != StatePassiveComplete {
		t.Fatalf("state = %q, want %q", got.State, StatePassiveComplete)
	}
}

func TestExtendToActive_AllowsWarnEvidence(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-extend-warn"

	seedPassiveComplete(t, core, runID, "https://peer.example", false)
	seedGradedEvidence(t, core, runID, SpecificationAreaTLS, GradeWarn)

	if err := core.ExtendToActive(ctx, runID); err != nil {
		t.Fatalf("ExtendToActive: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive {
		t.Fatal("warn evidence must still allow extend")
	}

	if got.State != StateActiveRunning {
		t.Fatalf("state = %q, want %q", got.State, StateActiveRunning)
	}
}

func TestExtendToActive_WritesBobUserIDOnPromotion(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-extend-bob"

	row := &TestRun{
		TestRunID:  runID,
		State:      StatePassiveComplete,
		TargetHost: "bob.example",
		CreatedAt:  now,
		UpdatedAt:  now,
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
			TestRunID:  id,
			State:      StatePassiveComplete,
			TargetHost: "lock.example",
			CreatedAt:  now,
			UpdatedAt:  now,
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

func TestExtendToActive_RefusesPersistedDiscoveryFailFromRunning(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-extend-running-fail-gate"

	seedPassiveRunningOptIn(t, core, runID)
	seedGradedEvidence(t, core, runID, SpecificationAreaDiscovery, GradeFail)

	err := core.ExtendToActive(ctx, runID)
	if !errors.Is(err, ErrSessionNotReady) {
		t.Fatalf("ExtendToActive error = %v, want ErrSessionNotReady", err)
	}

	got, getErr := core.GetTestRun(ctx, runID)
	if getErr != nil {
		t.Fatalf("GetTestRun: %v", getErr)
	}

	if got.IsActive {
		t.Fatal("failed-probe run must not take the active lock")
	}

	if got.State != StatePassiveRunning {
		t.Fatalf("state = %q, want %q", got.State, StatePassiveRunning)
	}
}

func seedPassiveRunningOptIn(t *testing.T, core *Core, runID string) {
	t.Helper()

	now := time.Now().Unix()
	row := &TestRun{
		TestRunID:   runID,
		State:       StatePassiveRunning,
		TargetHost:  "running.example",
		OptInActive: true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed running opt-in: %v", err)
	}
}
