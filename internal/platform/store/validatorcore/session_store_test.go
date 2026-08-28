// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestCreatePassiveSession_EnforcesInFlightCap(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.sessionCfg = SessionConfig{InFlightPassiveLimit: 1}
	ctx := t.Context()
	now := time.Now().Unix()

	first := &TestRun{
		TestRunID:  "run-cap-1",
		State:      StateCreated,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := core.CreatePassiveSession(ctx, first); err != nil {
		t.Fatalf("create first: %v", err)
	}

	second := &TestRun{
		TestRunID:  "run-cap-2",
		State:      StateCreated,
		TargetHost: "peer2.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	err := core.CreatePassiveSession(ctx, second)
	if !errors.Is(err, ErrInFlightPassiveLimit) {
		t.Fatalf("create second error = %v, want ErrInFlightPassiveLimit", err)
	}
}

func TestPassiveProbeTransitions(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-probe"

	row := &TestRun{
		TestRunID:  runID,
		State:      StateCreated,
		TargetHost: "probe.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := core.RunStartProbe(ctx, runID); err != nil {
		t.Fatalf("RunStartProbe: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StatePassiveRunning {
		t.Fatalf("state = %q, want %q", got.State, StatePassiveRunning)
	}

	if completeErr := core.CompletePassiveProbe(ctx, runID); completeErr != nil {
		t.Fatalf("CompletePassiveProbe: %v", completeErr)
	}

	got, err = core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after complete: %v", err)
	}

	if got.State != StatePassiveComplete {
		t.Fatalf("state = %q, want %q", got.State, StatePassiveComplete)
	}
}

func TestStopPassive_PassiveGuard(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-terminal"

	row := &TestRun{
		TestRunID:  runID,
		State:      StatePassiveComplete,
		TargetHost: "terminal.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := core.StopPassive(ctx, runID); err != nil {
		t.Fatalf("StopPassive: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateTerminalPass {
		t.Fatalf("state = %q, want %q", got.State, StateTerminalPass)
	}

	if SessionKindOf(got) != SessionKindPassiveOnly {
		t.Fatalf("session_kind = %q, want passive_only", SessionKindOf(got))
	}
}

func TestStartupSweep_TerminalizesExpiredPassiveInFlight(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.sessionCfg = SessionConfig{
		InFlightPassiveLimit:      10,
		CreatedTTLSeconds:         60,
		PassiveRunningTTLSeconds:  60,
		PassiveCompleteTTLSeconds: 60,
		TerminalRetentionDays:     30,
	}

	ctx := t.Context()
	stale := time.Now().Add(-2 * time.Minute).Unix()

	row := &TestRun{
		TestRunID:  "run-sweep",
		State:      StatePassiveRunning,
		TargetHost: "sweep.example",
		CreatedAt:  stale,
		UpdatedAt:  stale,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := core.sweepPassiveInFlightTTL(ctx); err != nil {
		t.Fatalf("sweepPassiveInFlightTTL: %v", err)
	}

	got, err := core.GetTestRun(ctx, "run-sweep")
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateTerminalFail {
		t.Fatalf("state = %q, want terminal_fail", got.State)
	}

	if SessionKindOf(got) != SessionKindPassiveOnly {
		t.Fatalf("session_kind = %q, want passive_only", SessionKindOf(got))
	}
}

func TestSweepPassiveCompleteTTL_TerminalizesExpiredSession(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.sessionCfg = SessionConfig{
		InFlightPassiveLimit:      10,
		PassiveCompleteTTLSeconds: 60,
	}

	ctx := t.Context()
	stale := time.Now().Add(-2 * time.Minute).Unix()

	row := &TestRun{
		TestRunID:  "run-pc-sweep",
		IsActive:   false,
		State:      StatePassiveComplete,
		TargetHost: "pc.example",
		CreatedAt:  stale,
		UpdatedAt:  stale,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := core.sweepPassiveCompleteTTL(ctx); err != nil {
		t.Fatalf("sweepPassiveCompleteTTL: %v", err)
	}

	got, err := core.GetTestRun(ctx, "run-pc-sweep")
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateTerminalFail {
		t.Fatalf("state = %q, want %q", got.State, StateTerminalFail)
	}

	if SessionKindOf(got) != SessionKindPassiveOnly {
		t.Fatalf("session_kind = %q, want %q", SessionKindOf(got), SessionKindPassiveOnly)
	}

	if got.TerminalReason == nil || *got.TerminalReason != "passive_complete_ttl_expired" {
		t.Fatalf("terminal_reason = %v, want passive_complete_ttl_expired", got.TerminalReason)
	}

	if got.FinishedAt == nil {
		t.Fatal("expected finished_at to be set")
	}
}

func TestSweepPassiveInFlightTTL_ReleasesInFlightCount(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.sessionCfg = SessionConfig{
		InFlightPassiveLimit:     1,
		CreatedTTLSeconds:        60,
		PassiveRunningTTLSeconds: 60,
	}

	ctx := t.Context()
	stale := time.Now().Add(-2 * time.Minute).Unix()

	rows := []struct {
		id     string
		state  string
		reason string
	}{
		{id: "run-sweep-created", state: StateCreated, reason: "created_ttl_expired"},
		{id: "run-sweep-running", state: StatePassiveRunning, reason: "passive_running_ttl_expired"},
	}

	for _, item := range rows {
		row := &TestRun{
			TestRunID:  item.id,
			IsActive:   false,
			State:      item.state,
			TargetHost: "cap.example",
			CreatedAt:  stale,
			UpdatedAt:  stale,
		}

		if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
			t.Fatalf("seed %s: %v", item.id, err)
		}
	}

	before, err := core.CountInFlightPassive(ctx)
	if err != nil {
		t.Fatalf("CountInFlightPassive before sweep: %v", err)
	}

	if before != 2 {
		t.Fatalf("in-flight count before sweep = %d, want 2", before)
	}

	if sweepErr := core.sweepPassiveInFlightTTL(ctx); sweepErr != nil {
		t.Fatalf("sweepPassiveInFlightTTL: %v", sweepErr)
	}

	after, err := core.CountInFlightPassive(ctx)
	if err != nil {
		t.Fatalf("CountInFlightPassive after sweep: %v", err)
	}

	if after != 0 {
		t.Fatalf("in-flight count after sweep = %d, want 0", after)
	}

	for _, item := range rows {
		got, getErr := core.GetTestRun(ctx, item.id)
		if getErr != nil {
			t.Fatalf("GetTestRun %s: %v", item.id, getErr)
		}

		if got.State != StateTerminalFail {
			t.Fatalf("%s state = %q, want %q", item.id, got.State, StateTerminalFail)
		}

		if SessionKindOf(got) != SessionKindPassiveOnly {
			t.Fatalf("%s session_kind = %q, want %q", item.id, SessionKindOf(got), SessionKindPassiveOnly)
		}

		if got.TerminalReason == nil || *got.TerminalReason != item.reason {
			t.Fatalf("%s terminal_reason = %v, want %q", item.id, got.TerminalReason, item.reason)
		}
	}
}

func TestSweepPassiveInFlightTTL_LeavesActiveInFlightUntouched(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.sessionCfg = SessionConfig{
		InFlightPassiveLimit:      10,
		CreatedTTLSeconds:         60,
		PassiveRunningTTLSeconds:  60,
		PassiveCompleteTTLSeconds: 60,
	}

	ctx := t.Context()
	stale := time.Now().Add(-2 * time.Minute).Unix()

	row := &TestRun{
		TestRunID:  "run-lb7-active",
		IsActive:   true,
		State:      StatePassiveRunning,
		TargetHost: "lb7.example",
		CreatedAt:  stale,
		UpdatedAt:  stale,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	before, err := core.GetTestRun(ctx, "run-lb7-active")
	if err != nil {
		t.Fatalf("GetTestRun before sweep: %v", err)
	}

	if sweepErr := core.sweepPassiveInFlightTTL(ctx); sweepErr != nil {
		t.Fatalf("sweepPassiveInFlightTTL: %v", sweepErr)
	}

	if completeErr := core.sweepPassiveCompleteTTL(ctx); completeErr != nil {
		t.Fatalf("sweepPassiveCompleteTTL: %v", completeErr)
	}

	got, err := core.GetTestRun(ctx, "run-lb7-active")
	if err != nil {
		t.Fatalf("GetTestRun after sweep: %v", err)
	}

	if got.State != before.State {
		t.Fatalf("state = %q, want unchanged %q", got.State, before.State)
	}

	if got.IsActive != before.IsActive {
		t.Fatalf("is_active = %v, want unchanged %v", got.IsActive, before.IsActive)
	}

	if got.UpdatedAt != before.UpdatedAt {
		t.Fatalf("updated_at = %d, want unchanged %d", got.UpdatedAt, before.UpdatedAt)
	}

	if got.TerminalReason != nil {
		t.Fatalf("terminal_reason = %v, want nil", got.TerminalReason)
	}

	if got.FinishedAt != nil {
		t.Fatalf("finished_at = %v, want nil", got.FinishedAt)
	}
}

func TestCreatePassiveSession_PKCollisionIsStoreError(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()

	row := &TestRun{
		TestRunID:  "run-dup",
		State:      StateCreated,
		TargetHost: "dup.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("first create: %v", err)
	}

	dupErr := core.CreatePassiveSession(ctx, row)

	var storeErr *StoreError
	if !errors.As(dupErr, &storeErr) || storeErr.Op != OpCreateSessionInsert {
		t.Fatalf("duplicate create error = %v, want OpCreateSessionInsert", dupErr)
	}

	if !errors.Is(storeErr.Err, gorm.ErrDuplicatedKey) {
		t.Fatalf("wrapped error = %v, want gorm.ErrDuplicatedKey", storeErr.Err)
	}
}
