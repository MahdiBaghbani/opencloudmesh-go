// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func seedActiveRunAt(t *testing.T, core *Core, runID, state string, updatedAt int64) {
	t.Helper()

	if err := core.DB().WithContext(t.Context()).Create(&TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        state,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		CreatedAt:    updatedAt,
		UpdatedAt:    updatedAt,
	}).Error; err != nil {
		t.Fatalf("seed active run %s: %v", runID, err)
	}
}

func staleActiveTimestamp(t *testing.T, core *Core) int64 {
	t.Helper()

	window := core.SessionConfig().StallTimeoutSeconds
	if window <= 0 {
		t.Fatal("test requires a positive stall timeout window")
	}

	return time.Now().Unix() - 2*int64(window)
}

func TestSweepStalledActiveSessions_InterruptsStalledRunAndPersistsStats(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	runID := "run-stall-interrupted"
	stale := staleActiveTimestamp(t, core)

	// Seed opted-in at create time: a later Updates call would auto-touch
	// updated_at and make the row look fresh to the sweep.
	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        StateCapabilityExercise,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		OptInStats:   true,
		CreatedAt:    stale,
		UpdatedAt:    stale,
	}).Error; err != nil {
		t.Fatalf("seed stalled opted-in run: %v", err)
	}

	before := time.Now().Unix()

	if err := core.SweepStalledActiveSessions(ctx); err != nil {
		t.Fatalf("SweepStalledActiveSessions: %v", err)
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

	if got.TerminalReason == nil || *got.TerminalReason != "stall_inactivity_expired" {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, "stall_inactivity_expired")
	}

	if got.OverallGrade != nil {
		t.Fatalf("overall_grade = %v, want nil for interrupted", got.OverallGrade)
	}

	if got.FinishedAt == nil || *got.FinishedAt < before {
		t.Fatalf("finished_at = %v, want a stamp >= %d", got.FinishedAt, before)
	}

	// The stats write requires finished_at, so a persisted stats row proves the
	// state/lock transition committed before statistics persistence ran.
	if got.StatsWrittenAt == nil || *got.StatsWrittenAt < *got.FinishedAt {
		t.Fatalf("stats_written_at = %v, want a stamp >= finished_at %d", got.StatsWrittenAt, *got.FinishedAt)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw count = %d, want 1 after stall interruption", rawCount)
	}
}

func TestSweepStalledActiveSessions_SkipsFreshActiveRun(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	runID := "run-stall-fresh"
	seedActiveRunAt(t, core, runID, StateCapabilityExercise, time.Now().Unix())

	if err := core.SweepStalledActiveSessions(ctx); err != nil {
		t.Fatalf("SweepStalledActiveSessions: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive || got.State != StateCapabilityExercise {
		t.Fatalf("is_active=%v state=%q, want untouched active capability_exercise", got.IsActive, got.State)
	}

	if got.FinishedAt != nil {
		t.Fatalf("finished_at = %v, want nil", got.FinishedAt)
	}
}

func TestSweepStalledActiveSessions_ProbeSessionSurvives(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	runID := "run-stall-probe"
	probeUserID := "018f3c7a-9c2e-7b1d-8f4a-2e6c1d9a5b30"
	stale := staleActiveTimestamp(t, core)

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        StateReverseAwaitingShare,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		BobUserID:    &probeUserID,
		CreatedAt:    stale,
		UpdatedAt:    stale,
	}).Error; err != nil {
		t.Fatalf("seed stalled probe-linked run: %v", err)
	}

	if err := core.SweepStalledActiveSessions(ctx); err != nil {
		t.Fatalf("SweepStalledActiveSessions: %v", err)
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

func TestSweepStalledActiveSessions_StallReasonMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		state      string
		wantReason string
	}{
		{name: "capability exercise", state: StateCapabilityExercise, wantReason: "stall_inactivity_expired"},
		{name: "reverse awaiting share", state: StateReverseAwaitingShare, wantReason: "reverse_share_timeout"},
		{name: "reverse awaiting invite", state: StateReverseAwaitingInvite, wantReason: "reverse_invite_timeout"},
		// A non-terminal state with no dedicated mapping is still swept: the
		// selection guards on not-terminal, never on a list of forward names.
		{name: "forward share sent", state: StateForwardShareSent, wantReason: "stall_inactivity_expired"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()

			runID := "run-stall-reason"
			seedActiveRunAt(t, core, runID, tc.state, staleActiveTimestamp(t, core))

			if err := core.SweepStalledActiveSessions(ctx); err != nil {
				t.Fatalf("SweepStalledActiveSessions: %v", err)
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

			if got.TerminalReason == nil || *got.TerminalReason != tc.wantReason {
				t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, tc.wantReason)
			}
		})
	}
}

func TestSweepStalledActiveSessions_ReverseShareTimeoutShortensWindow(t *testing.T) {
	t.Parallel()

	// Both runs sit idle for 120 seconds: past the 60-second reverse-share
	// budget, well inside the 3600-second stall window.
	cfg := SessionConfig{
		InFlightPassiveLimit:       1,
		StallTimeoutSeconds:        3600,
		ReverseShareTimeoutSeconds: 60,
	}

	t.Run("reverse awaiting share sweeps at the reverse cutoff", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		core.SetSessionConfig(cfg)

		ctx := t.Context()

		runID := "run-stall-reverse-window"
		seedActiveRunAt(t, core, runID, StateReverseAwaitingShare, time.Now().Unix()-120)

		if err := core.SweepStalledActiveSessions(ctx); err != nil {
			t.Fatalf("SweepStalledActiveSessions: %v", err)
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

		if got.TerminalReason == nil || *got.TerminalReason != ReasonReverseShareTimeout {
			t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, ReasonReverseShareTimeout)
		}
	})

	t.Run("capability exercise keeps the stall cutoff", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		core.SetSessionConfig(cfg)

		ctx := t.Context()

		runID := "run-stall-forward-window"
		seedActiveRunAt(t, core, runID, StateCapabilityExercise, time.Now().Unix()-120)

		if err := core.SweepStalledActiveSessions(ctx); err != nil {
			t.Fatalf("SweepStalledActiveSessions: %v", err)
		}

		got, err := core.GetTestRun(ctx, runID)
		if err != nil {
			t.Fatalf("GetTestRun: %v", err)
		}

		if !got.IsActive || got.State != StateCapabilityExercise {
			t.Fatalf("is_active=%v state=%q, want untouched active capability_exercise inside the stall window",
				got.IsActive, got.State)
		}

		if got.FinishedAt != nil {
			t.Fatalf("finished_at = %v, want nil", got.FinishedAt)
		}
	})
}

func TestSweepStalledActiveSessions_DisabledWindowSkipsSweep(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetSessionConfig(SessionConfig{InFlightPassiveLimit: 1})

	ctx := t.Context()

	runID := "run-stall-disabled"
	seedActiveRunAt(t, core, runID, StateCapabilityExercise, time.Now().Unix()-86400)

	if err := core.SweepStalledActiveSessions(ctx); err != nil {
		t.Fatalf("SweepStalledActiveSessions: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive || got.State != StateCapabilityExercise {
		t.Fatalf("is_active=%v state=%q, want untouched active capability_exercise", got.IsActive, got.State)
	}
}
