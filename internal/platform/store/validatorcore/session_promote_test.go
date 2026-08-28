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

func TestFindOldestReadyOptInWaiter_OrdersOldestReady(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	older := now - 20
	newer := now - 5

	seedReadyWaiter(t, core, "run-waiter-new", newer)
	seedReadyWaiter(t, core, "run-waiter-old", older)
	seedPassiveRunningOptIn(t, core, "run-not-ready")

	got, err := core.FindOldestReadyOptInWaiter(ctx)
	if err != nil {
		t.Fatalf("FindOldestReadyOptInWaiter: %v", err)
	}

	if got == nil || got.TestRunID != "run-waiter-old" {
		t.Fatalf("oldest waiter = %v, want run-waiter-old", got)
	}
}

func TestFindOneActive_DoesNotSeeReadyWaiter(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	seedReadyWaiter(t, core, "run-waiter-hidden", time.Now().Unix())

	if _, err := core.FindOneActive(ctx, LocalIdentityA); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("FindOneActive = %v, want ErrRecordNotFound", err)
	}
}

func TestPromoteOldestReadyWaiter_TakesFreeSlot(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	seedReadyWaiter(t, core, "run-promote-free", time.Now().Unix())

	if err := core.PromoteOldestReadyWaiter(ctx); err != nil {
		t.Fatalf("PromoteOldestReadyWaiter: %v", err)
	}

	got, err := core.GetTestRun(ctx, "run-promote-free")
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive || got.State != StateActiveRunning {
		t.Fatalf("is_active=%v state=%q, want active_running", got.IsActive, got.State)
	}
}

func TestPromoteOldestReadyWaiter_LeavesWaiterWhenBusy(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:  "run-holder",
		IsActive:   true,
		State:      StateActiveRunning,
		TargetHost: "lock.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}).Error; err != nil {
		t.Fatalf("seed holder: %v", err)
	}

	seedReadyWaiter(t, core, "run-promote-busy", now)

	if err := core.PromoteOldestReadyWaiter(ctx); err != nil {
		t.Fatalf("PromoteOldestReadyWaiter: %v", err)
	}

	got, err := core.GetTestRun(ctx, "run-promote-busy")
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive || got.State != StatePassiveRunning {
		t.Fatalf("busy waiter is_active=%v state=%q", got.IsActive, got.State)
	}

	if got.PassiveReadyAt == nil {
		t.Fatal("busy waiter must keep passive_ready_at")
	}
}

func TestSweepPassiveInFlightTTL_SkipsReadyWaiter(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.sessionCfg = SessionConfig{
		InFlightPassiveLimit:     10,
		CreatedTTLSeconds:        60,
		PassiveRunningTTLSeconds: 60,
	}

	ctx := t.Context()
	stale := time.Now().Add(-2 * time.Minute).Unix()

	seedReadyWaiter(t, core, "run-ready-exempt", stale)

	row := &TestRun{
		TestRunID:  "run-opt-out-stale",
		State:      StatePassiveRunning,
		TargetHost: "sweep.example",
		CreatedAt:  stale,
		UpdatedAt:  stale,
	}
	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed opt-out: %v", err)
	}

	if err := core.sweepPassiveInFlightTTL(ctx); err != nil {
		t.Fatalf("sweepPassiveInFlightTTL: %v", err)
	}

	waiter, err := core.GetTestRun(ctx, "run-ready-exempt")
	if err != nil {
		t.Fatalf("GetTestRun waiter: %v", err)
	}

	if waiter.State != StatePassiveRunning {
		t.Fatalf("ready waiter state = %q, want passive_running", waiter.State)
	}

	expired, err := core.GetTestRun(ctx, "run-opt-out-stale")
	if err != nil {
		t.Fatalf("GetTestRun opt-out: %v", err)
	}

	if expired.State != StateTerminalFail {
		t.Fatalf("opt-out state = %q, want terminal_fail", expired.State)
	}
}

func TestStopPassive_AbandonsReadyWaiter(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	seedReadyWaiter(t, core, "run-stop-waiter", time.Now().Unix())

	if err := core.StopPassive(ctx, "run-stop-waiter"); err != nil {
		t.Fatalf("StopPassive: %v", err)
	}

	got, err := core.GetTestRun(ctx, "run-stop-waiter")
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateTerminalFail {
		t.Fatalf("state = %q, want %q", got.State, StateTerminalFail)
	}

	if got.TerminalReason == nil || *got.TerminalReason != ReasonOperatorAborted {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, ReasonOperatorAborted)
	}
}

func TestStartupMaintenance_PromotesReadyWaiterBeforePassiveTTL(t *testing.T) { //nolint:paralleltest // resets the process-local first-maintenance guard
	resetStartupFirstMaintenanceOnce(t)

	core := openTestCore(t)
	core.SetSessionConfig(SessionConfig{
		InFlightPassiveLimit:      10,
		CreatedTTLSeconds:         60,
		PassiveRunningTTLSeconds:  60,
		PassiveCompleteTTLSeconds: 3600,
		TerminalRetentionDays:     30,
		StallTimeoutSeconds:       3600,
	})

	ctx := t.Context()
	now := time.Now().Unix()
	stale := now - 180

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:  "run-startup-leftover",
		IsActive:   true,
		State:      StateActiveRunning,
		TargetHost: "boot.example",
		CreatedAt:  stale,
		UpdatedAt:  stale,
	}).Error; err != nil {
		t.Fatalf("seed leftover: %v", err)
	}

	seedReadyWaiter(t, core, "run-startup-waiter", stale)

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:  "run-startup-stale-created",
		State:      StateCreated,
		TargetHost: "boot.example",
		CreatedAt:  stale,
		UpdatedAt:  stale,
	}).Error; err != nil {
		t.Fatalf("seed created: %v", err)
	}

	if err := core.startupMaintenance(ctx); err != nil {
		t.Fatalf("startupMaintenance: %v", err)
	}

	leftover, err := core.GetTestRun(ctx, "run-startup-leftover")
	if err != nil {
		t.Fatalf("GetTestRun leftover: %v", err)
	}

	if leftover.IsActive || leftover.State != StateInterrupted {
		t.Fatalf("leftover is_active=%v state=%q, want interrupted", leftover.IsActive, leftover.State)
	}

	waiter, err := core.GetTestRun(ctx, "run-startup-waiter")
	if err != nil {
		t.Fatalf("GetTestRun waiter: %v", err)
	}

	if !waiter.IsActive || waiter.State != StateActiveRunning {
		t.Fatalf("waiter is_active=%v state=%q, want promoted", waiter.IsActive, waiter.State)
	}

	created, err := core.GetTestRun(ctx, "run-startup-stale-created")
	if err != nil {
		t.Fatalf("GetTestRun created: %v", err)
	}

	if created.State != StateTerminalFail {
		t.Fatalf("stale created state = %q, want terminal_fail", created.State)
	}
}

func seedReadyWaiter(t *testing.T, core *Core, runID string, readyAt int64) {
	t.Helper()

	row := &TestRun{
		TestRunID:      runID,
		State:          StatePassiveRunning,
		TargetHost:     "waiter.example",
		OptInActive:    true,
		PassiveReadyAt: &readyAt,
		CreatedAt:      readyAt,
		UpdatedAt:      readyAt,
	}

	if err := core.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed ready waiter %s: %v", runID, err)
	}
}
