// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"
)

func TestWriteTerminalObserved_MatchTerminalizes(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-observed-match"

	observed := seedObservedActiveRun(
		t,
		core,
		runID,
		1_700_000_100,
	)

	if err := core.WriteTerminalObserved(
		ctx,
		observed.TestRunID,
		true,
		observed.State,
		observed.UpdatedAt,
		observedDriveTimeoutUpdate(),
	); err != nil {
		t.Fatalf("WriteTerminalObserved: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive {
		t.Fatal("is_active = 1, want 0")
	}

	if got.State != StateInterrupted {
		t.Fatalf("state = %q, want %q", got.State, StateInterrupted)
	}

	if got.TerminalReason == nil || *got.TerminalReason != ReasonActiveDriveTimeout {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, ReasonActiveDriveTimeout)
	}

	if got.FinishedAt == nil {
		t.Fatal("finished_at = nil, want stamped")
	}
}

func TestWriteTerminalObserved_StateRaceMisses(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-observed-state-race"

	observed := seedObservedActiveRun(
		t,
		core,
		runID,
		1_700_000_200,
	)
	setStateKeepUpdatedAt(t, core, runID, StateInviteMinted)

	err := core.WriteTerminalObserved(
		ctx,
		observed.TestRunID,
		true,
		observed.State,
		observed.UpdatedAt,
		observedDriveTimeoutUpdate(),
	)
	if !errors.Is(err, ErrStateTransitionMiss) {
		t.Fatalf("WriteTerminalObserved error = %v, want ErrStateTransitionMiss", err)
	}

	requireLiveObservedRun(
		t,
		core,
		runID,
		StateInviteMinted,
		observed.UpdatedAt,
	)
}

func TestWriteTerminalObserved_UpdatedAtRaceMisses(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-observed-updated-at-race"

	observed := seedObservedActiveRun(
		t,
		core,
		runID,
		1_700_000_300,
	)
	fresh := observed.UpdatedAt + 15
	pinUpdatedAt(t, core, runID, fresh)

	err := core.WriteTerminalObserved(
		ctx,
		observed.TestRunID,
		true,
		observed.State,
		observed.UpdatedAt,
		observedDriveTimeoutUpdate(),
	)
	if !errors.Is(err, ErrStateTransitionMiss) {
		t.Fatalf("WriteTerminalObserved error = %v, want ErrStateTransitionMiss", err)
	}

	requireLiveObservedRun(
		t,
		core,
		runID,
		StateActiveRunning,
		fresh,
	)
}

func TestWriteTerminalObserved_WatchdogMissIsBenign(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-observed-watchdog-miss"

	// Same seam the runner watchdog uses: observe the row, then write
	// that exact state and updated_at. A later touch must miss, and a
	// retry of the stale snapshot must not terminalize.
	observed := seedObservedActiveRun(
		t,
		core,
		runID,
		1_700_000_400,
	)

	fresh := observed.UpdatedAt + 30
	pinUpdatedAt(t, core, runID, fresh)

	first := core.WriteTerminalObserved(
		ctx,
		observed.TestRunID,
		true,
		observed.State,
		observed.UpdatedAt,
		observedDriveTimeoutUpdate(),
	)
	if !errors.Is(first, ErrStateTransitionMiss) {
		t.Fatalf("first WriteTerminalObserved error = %v, want ErrStateTransitionMiss", first)
	}

	retry := core.WriteTerminalObserved(
		ctx,
		observed.TestRunID,
		true,
		observed.State,
		observed.UpdatedAt,
		observedDriveTimeoutUpdate(),
	)
	if !errors.Is(retry, ErrStateTransitionMiss) {
		t.Fatalf("retry WriteTerminalObserved error = %v, want ErrStateTransitionMiss", retry)
	}

	requireLiveObservedRun(
		t,
		core,
		runID,
		StateActiveRunning,
		fresh,
	)
}

func observedDriveTimeoutUpdate() ActiveTerminalUpdate {
	return ActiveTerminalUpdate{
		State:          StateInterrupted,
		TerminalReason: ReasonActiveDriveTimeout,
	}
}

func seedObservedActiveRun(
	t *testing.T,
	core *Core,
	runID string,
	updatedAt int64,
) *TestRun {
	t.Helper()

	seedActiveRunInState(t, core, runID, StateActiveRunning)
	pinUpdatedAt(t, core, runID, updatedAt)

	got, err := core.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateActiveRunning || got.UpdatedAt != updatedAt || !got.IsActive {
		t.Fatalf(
			"observed seed is_active=%v state=%q updated_at=%d, want active %q @ %d",
			got.IsActive,
			got.State,
			got.UpdatedAt,
			StateActiveRunning,
			updatedAt,
		)
	}

	return got
}

func pinUpdatedAt(t *testing.T, core *Core, runID string, at int64) {
	t.Helper()

	if err := core.DB().WithContext(t.Context()).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		UpdateColumn(colUpdatedAt, at).Error; err != nil {
		t.Fatalf("pin updated_at: %v", err)
	}
}

func setStateKeepUpdatedAt(t *testing.T, core *Core, runID, state string) {
	t.Helper()

	if err := core.DB().WithContext(t.Context()).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		UpdateColumn(colState, state).Error; err != nil {
		t.Fatalf("set state: %v", err)
	}
}

func requireLiveObservedRun(
	t *testing.T,
	core *Core,
	runID string,
	wantState string,
	wantUpdatedAt int64,
) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive {
		t.Fatal("is_active = 0, want live")
	}

	if got.State != wantState {
		t.Fatalf("state = %q, want live %q", got.State, wantState)
	}

	if got.UpdatedAt != wantUpdatedAt {
		t.Fatalf("updated_at = %d, want %d", got.UpdatedAt, wantUpdatedAt)
	}

	if got.FinishedAt != nil {
		t.Fatalf("finished_at = %v, want nil on a live row", got.FinishedAt)
	}

	if got.TerminalReason != nil {
		t.Fatalf("terminal_reason = %v, want nil on a live row", got.TerminalReason)
	}
}
