// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"sync"
	"testing"
	"time"
)

// resetStartupFirstMaintenanceOnce re-arms the process-local first
// maintenance guard. Only sequential tests may call it: parallel tests are
// paused while sequential tests run, so the reset never races another test.
func resetStartupFirstMaintenanceOnce(t *testing.T) {
	t.Helper()

	startupFirstMaintenanceOnce = sync.Once{}

	t.Cleanup(func() {
		startupFirstMaintenanceOnce = sync.Once{}
	})
}

func TestTerminalizeUnrecoverableActiveRuns_InterruptsLeftoverActiveRuns(t *testing.T) {
	t.Parallel()

	// Every non-terminal name the schema permits is interrupted: the
	// recovery guard excludes the terminal set instead of enumerating
	// forward names, so the full enum is the name-agnostic proof.
	for _, state := range allNonTerminalStates() {
		t.Run(state, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			now := time.Now().Unix()

			// The one-active-run index allows a single lock holder per
			// store, so each state gets its own store.
			runID := "run-recovery-" + state

			if err := core.DB().WithContext(ctx).Create(&TestRun{
				TestRunID:  runID,
				IsActive:   true,
				State:      state,
				TargetHost: "recovery.example",
				CreatedAt:  now,
				UpdatedAt:  now,
			}).Error; err != nil {
				t.Fatalf("seed leftover active run %s: %v", state, err)
			}

			// A passive in-flight row carries no active lock and is never
			// recovered.
			passiveID := "run-recovery-passive"

			if err := core.DB().WithContext(ctx).Create(&TestRun{
				TestRunID:  passiveID,
				IsActive:   false,
				State:      StatePassiveRunning,
				TargetHost: "recovery.example",
				CreatedAt:  now,
				UpdatedAt:  now,
			}).Error; err != nil {
				t.Fatalf("seed passive run: %v", err)
			}

			before := time.Now().Unix()

			if err := core.terminalizeUnrecoverableActiveRuns(ctx); err != nil {
				t.Fatalf("terminalizeUnrecoverableActiveRuns: %v", err)
			}

			got, err := core.GetTestRun(ctx, runID)
			if err != nil {
				t.Fatalf("GetTestRun %s: %v", runID, err)
			}

			if got.IsActive {
				t.Fatalf("%s is_active = 1, want 0", runID)
			}

			if got.State != StateInterrupted {
				t.Fatalf("%s state = %q, want %q", runID, got.State, StateInterrupted)
			}

			if got.TerminalReason == nil || *got.TerminalReason != "startup_unrecoverable_active" {
				t.Fatalf("%s terminal_reason = %v, want %q", runID, got.TerminalReason, "startup_unrecoverable_active")
			}

			if got.FinishedAt == nil || *got.FinishedAt < before {
				t.Fatalf("%s finished_at = %v, want a stamp >= %d", runID, got.FinishedAt, before)
			}

			passive, err := core.GetTestRun(ctx, passiveID)
			if err != nil {
				t.Fatalf("GetTestRun passive: %v", err)
			}

			if passive.IsActive || passive.State != StatePassiveRunning {
				t.Fatalf(
					"passive is_active=%v state=%q, want untouched passive_running",
					passive.IsActive,
					passive.State,
				)
			}
		})
	}
}

func TestTerminalizeUnrecoverableActiveRuns_LeavesTerminalHybridForLockReconciliation(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()

	// A hybrid row already holds a terminal state; startup recovery leaves it
	// for the stall sweep's lock-clearing reconciliation.
	hybridID := "run-recovery-hybrid"
	hybridReason := "completed"

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      hybridID,
		IsActive:       true,
		State:          StateTerminalPass,
		TargetHost:     "recovery.example",
		TerminalReason: &hybridReason,
		FinishedAt:     &now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed hybrid run: %v", err)
	}

	if err := core.terminalizeUnrecoverableActiveRuns(ctx); err != nil {
		t.Fatalf("terminalizeUnrecoverableActiveRuns: %v", err)
	}

	hybrid, err := core.GetTestRun(ctx, hybridID)
	if err != nil {
		t.Fatalf("GetTestRun hybrid: %v", err)
	}

	if !hybrid.IsActive || hybrid.State != StateTerminalPass {
		t.Fatalf("hybrid is_active=%v state=%q, want untouched active terminal_pass", hybrid.IsActive, hybrid.State)
	}

	if hybrid.TerminalReason == nil || *hybrid.TerminalReason != hybridReason {
		t.Fatalf("hybrid terminal_reason = %v, want unchanged %q", hybrid.TerminalReason, hybridReason)
	}
}

func TestTerminalizeUnrecoverableActiveRuns_ProbeSessionSurvives(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	runID := "run-recovery-probe"
	probeUserID := "018f3c7a-9c2e-7b1d-8f4a-2e6c1d9a5b30"
	now := time.Now().Unix()

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        StateReverseAwaitingShare,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		BobUserID:    &probeUserID,
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed probe-linked active run: %v", err)
	}

	if err := core.terminalizeUnrecoverableActiveRuns(ctx); err != nil {
		t.Fatalf("terminalizeUnrecoverableActiveRuns: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v (interrupted run must not be deleted)", err)
	}

	if got.State != StateInterrupted {
		t.Fatalf("state = %q, want %q", got.State, StateInterrupted)
	}

	if got.BobUserID == nil || *got.BobUserID != probeUserID {
		t.Fatalf("bob_user_id = %v, want preserved %q", got.BobUserID, probeUserID)
	}

	if got.HarvestedAt != nil || got.HarvestReason != nil {
		t.Fatalf("harvest markers = (%v, %v), want both nil", got.HarvestedAt, got.HarvestReason)
	}
}

func TestTerminalizeUnrecoverableActiveRuns_PersistsTerminalStats(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	runID := "run-recovery-stats"
	now := time.Now().Unix()

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        StateActiveRunning,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		OptInStats:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed opted-in leftover run: %v", err)
	}

	if err := core.terminalizeUnrecoverableActiveRuns(ctx); err != nil {
		t.Fatalf("terminalizeUnrecoverableActiveRuns: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.FinishedAt == nil {
		t.Fatal("finished_at = nil, want a stamp")
	}

	if got.StatsWrittenAt == nil || *got.StatsWrittenAt < *got.FinishedAt {
		t.Fatalf("stats_written_at = %v, want a stamp >= finished_at %d", got.StatsWrittenAt, *got.FinishedAt)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw count = %d, want 1 after startup recovery", rawCount)
	}
}

func TestAttach_StartupRecoveryRunsOncePerProcess(t *testing.T) { //nolint:paralleltest // resets the process-local first-maintenance guard, which parallel tests must never observe mid-reset
	resetStartupFirstMaintenanceOnce(t)

	sqlCore := openPeerStore(t)
	ctx := t.Context()

	core, err := Attach(sqlCore.DB(), DefaultSessionConfig())
	if err != nil {
		t.Fatalf("first Attach: %v", err)
	}

	// This row belongs to the current process: it took the active lock after
	// the first Attach, so a re-attach must never interrupt it.
	runID := "run-recovery-owned"
	seedActiveRunInState(t, core, runID, StateActiveRunning)

	if _, attachErr := Attach(sqlCore.DB(), DefaultSessionConfig()); attachErr != nil {
		t.Fatalf("second Attach: %v", attachErr)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive || got.State != StateActiveRunning {
		t.Fatalf(
			"after second Attach is_active=%v state=%q, want untouched active run owned by this process",
			got.IsActive,
			got.State,
		)
	}

	// Re-arming the guard lets a later Attach run first maintenance again,
	// proving the guard alone protected the row.
	resetStartupFirstMaintenanceOnce(t)

	if _, attachErr := Attach(sqlCore.DB(), DefaultSessionConfig()); attachErr != nil {
		t.Fatalf("third Attach after re-arm: %v", attachErr)
	}

	got, err = core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after re-arm: %v", err)
	}

	if got.IsActive || got.State != StateInterrupted {
		t.Fatalf("after re-arm is_active=%v state=%q, want interrupted inactive", got.IsActive, got.State)
	}

	if got.TerminalReason == nil || *got.TerminalReason != "startup_unrecoverable_active" {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, "startup_unrecoverable_active")
	}
}

func TestAttach_SecondAttachSkipsStallSweep(t *testing.T) { //nolint:paralleltest // resets the process-local first-maintenance guard, which parallel tests must never observe mid-reset
	resetStartupFirstMaintenanceOnce(t)

	sqlCore := openPeerStore(t)
	ctx := t.Context()

	cfg := DefaultSessionConfig()
	cfg.StallTimeoutSeconds = 3600

	core, err := Attach(sqlCore.DB(), cfg)
	if err != nil {
		t.Fatalf("first Attach: %v", err)
	}

	// Seed a stale active row after the first Attach: its updated_at is well
	// past the stall timeout, so a stall sweep on re-attach would interrupt
	// it. The first maintenance already ran, so the row belongs to this
	// process and both one-shot passes must skip it.
	runID := "run-stall-gated"
	seedActiveRunInState(t, core, runID, StateActiveRunning)

	stale := time.Now().Unix() - 2*3600

	if ageErr := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		Update("updated_at", stale).Error; ageErr != nil {
		t.Fatalf("age run updated_at: %v", ageErr)
	}

	if _, attachErr := Attach(sqlCore.DB(), cfg); attachErr != nil {
		t.Fatalf("second Attach: %v", attachErr)
	}

	assertActiveInState(t, core, runID, StateActiveRunning)

	// Re-arming the guard lets a later Attach run first maintenance again:
	// the same row is interrupted, proving it was sweep-eligible all along
	// and only the guard spared it.
	resetStartupFirstMaintenanceOnce(t)

	if _, attachErr := Attach(sqlCore.DB(), cfg); attachErr != nil {
		t.Fatalf("third Attach after re-arm: %v", attachErr)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after re-arm: %v", err)
	}

	if got.IsActive || got.State != StateInterrupted {
		t.Fatalf("after re-arm is_active=%v state=%q, want interrupted inactive", got.IsActive, got.State)
	}

	if got.TerminalReason == nil || *got.TerminalReason != "startup_unrecoverable_active" {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, "startup_unrecoverable_active")
	}
}
