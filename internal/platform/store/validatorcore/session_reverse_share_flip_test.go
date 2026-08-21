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

// failingStatsHostHasher fails every hash so tests can inject terminal-stats
// write failures after the state transition already committed.
type failingStatsHostHasher struct{}

func (failingStatsHostHasher) HashHost(string) (string, error) {
	return "", errors.New("injected host hash failure")
}

func (failingStatsHostHasher) HashStatsK(string) (string, error) {
	return "", errors.New("injected stats key failure")
}

// seedInterruptedRun seeds an inactive interrupted row with the given reason,
// bypassing the release path so statistics stay unwritten until the test
// drives them.
func seedInterruptedRun(t *testing.T, core *Core, runID, reason string, optInStats bool) {
	t.Helper()

	now := time.Now().Unix()

	if err := core.DB().WithContext(t.Context()).Create(&TestRun{
		TestRunID:      runID,
		IsActive:       false,
		State:          StateInterrupted,
		SessionKind:    SessionKindActiveFull,
		TargetOrigin:   "https://peer.example",
		TargetHost:     "peer.example",
		TerminalReason: &reason,
		FinishedAt:     &now,
		OptInStats:     optInStats,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed interrupted run %s: %v", runID, err)
	}
}

func countStatsRaw(t *testing.T, core *Core) int64 {
	t.Helper()

	var count int64
	if err := core.DB().WithContext(t.Context()).Model(&StatsRaw{}).Count(&count).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	return count
}

func TestFlipLateReverseShareToPass_FlipsTimeoutInterrupted(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	runID := "run-flip-timeout"
	seedInterruptedRun(t, core, runID, ReasonReverseShareTimeout, true)

	before, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	passed, err := core.FlipLateReverseShareToPass(ctx, runID)
	if err != nil {
		t.Fatalf("FlipLateReverseShareToPass: %v", err)
	}

	if !passed {
		t.Fatal("passed = false, want the timeout-interrupted row to flip")
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateTerminalPass {
		t.Fatalf("state = %q, want %q", got.State, StateTerminalPass)
	}

	if got.TerminalReason == nil || *got.TerminalReason != ReasonLateReverseShare {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, ReasonLateReverseShare)
	}

	if got.IsActive {
		t.Fatal("is_active = 1, want the flip to never retake the active lock")
	}

	if got.FinishedAt == nil || *got.FinishedAt != *before.FinishedAt {
		t.Fatalf("finished_at = %v, want preserved %d", got.FinishedAt, *before.FinishedAt)
	}

	if got.StatsWrittenAt == nil {
		t.Fatal("stats_written_at = nil, want the flip's stats transaction to stamp it")
	}

	if count := countStatsRaw(t, core); count != 1 {
		t.Fatalf("stats_raw count = %d, want 1", count)
	}
}

func TestFlipLateReverseShareToPass_DuplicateDeliveryDoesNotDoubleCount(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	runID := "run-flip-duplicate"
	seedInterruptedRun(t, core, runID, ReasonReverseShareTimeout, true)

	if _, err := core.FlipLateReverseShareToPass(ctx, runID); err != nil {
		t.Fatalf("FlipLateReverseShareToPass: %v", err)
	}

	// A duplicate delivery of the same share re-enters the flip: the state
	// CAS misses, the reload confirms terminal_pass, and the keyed stats
	// upsert is a no-op for counting purposes.
	passed, err := core.FlipLateReverseShareToPass(ctx, runID)
	if err != nil {
		t.Fatalf("second FlipLateReverseShareToPass: %v", err)
	}

	if !passed {
		t.Fatal("second passed = false, want the already-passed row to confirm")
	}

	if count := countStatsRaw(t, core); count != 1 {
		t.Fatalf("stats_raw count after duplicate = %d, want 1 (no double count)", count)
	}

	var agg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&agg).Error; err != nil {
		t.Fatalf("load stats aggregate: %v", err)
	}

	if agg.TotalSessions != 1 {
		t.Fatalf("aggregate total_sessions = %d, want 1 (no double count)", agg.TotalSessions)
	}
}

func TestFlipLateReverseShareToPass_RefusesUnflippableRows(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	// capability_exercise stalls read as inactivity expiry and must never arm
	// the late flip; startup-unrecoverable rows are equally off-limits.
	seedInterruptedRun(t, core, "run-flip-stall", "stall_inactivity_expired", false)
	seedInterruptedRun(t, core, "run-flip-unrecoverable", "startup_unrecoverable_active", false)

	for _, runID := range []string{"run-flip-stall", "run-flip-unrecoverable"} {
		passed, err := core.FlipLateReverseShareToPass(ctx, runID)
		if err != nil {
			t.Fatalf("%s: FlipLateReverseShareToPass: %v", runID, err)
		}

		if passed {
			t.Fatalf("%s: passed = true, want the row to stay interrupted", runID)
		}

		got, err := core.GetTestRun(ctx, runID)
		if err != nil {
			t.Fatalf("%s: GetTestRun: %v", runID, err)
		}

		if got.State != StateInterrupted {
			t.Fatalf("%s: state = %q, want unchanged %q", runID, got.State, StateInterrupted)
		}
	}

	// A pruned or never-existing row is evidence-only, not an error.
	passed, err := core.FlipLateReverseShareToPass(ctx, "run-flip-missing")
	if err != nil {
		t.Fatalf("missing row: FlipLateReverseShareToPass: %v", err)
	}

	if passed {
		t.Fatal("missing row: passed = true, want false")
	}
}

func TestFlipLateReverseShareToPass_StateSurvivesStatsFailureThenHeals(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(failingStatsHostHasher{})

	ctx := t.Context()

	runID := "run-flip-stats-fail"
	seedInterruptedRun(t, core, runID, ReasonReverseShareTimeout, true)

	passed, err := core.FlipLateReverseShareToPass(ctx, runID)
	if err == nil {
		t.Fatal("flip error = nil, want the injected stats failure to surface")
	}

	if !passed {
		t.Fatal("passed = false, want the state flip to commit before stats run")
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateTerminalPass {
		t.Fatalf("state = %q, want %q even with stats down", got.State, StateTerminalPass)
	}

	if got.StatsWrittenAt != nil {
		t.Fatalf("stats_written_at = %v, want nil while stats are failing", got.StatsWrittenAt)
	}

	if count := countStatsRaw(t, core); count != 0 {
		t.Fatalf("stats_raw count = %d, want 0 while stats are failing", count)
	}

	// The durable retry heals the missing stats row through the same seam.
	core.SetStatsHostHasher(testStatsHostHasher(t))

	if retryErr := core.RetryTerminalStats(ctx, runID); retryErr != nil {
		t.Fatalf("RetryTerminalStats: %v", retryErr)
	}

	healed, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after heal: %v", err)
	}

	if healed.StatsWrittenAt == nil {
		t.Fatal("stats_written_at = nil after retry, want stamped")
	}

	if count := countStatsRaw(t, core); count != 1 {
		t.Fatalf("stats_raw count after retry = %d, want 1", count)
	}
}

func TestHealMissingTerminalStats_HealsOnlyOptedInTerminalGaps(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	finished := time.Now().Unix()

	// Opted-in terminal row whose stats never landed: the heal target.
	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:    "run-heal-gap",
		IsActive:     false,
		State:        StateTerminalPass,
		SessionKind:  SessionKindActiveFull,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		FinishedAt:   &finished,
		OptInStats:   true,
		CreatedAt:    finished,
		UpdatedAt:    finished,
	}).Error; err != nil {
		t.Fatalf("seed heal gap: %v", err)
	}

	// Not opted in: never touched by the heal.
	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:    "run-heal-opted-out",
		IsActive:     false,
		State:        StateTerminalPass,
		SessionKind:  SessionKindActiveFull,
		TargetOrigin: "https://other.example",
		TargetHost:   "other.example",
		FinishedAt:   &finished,
		OptInStats:   false,
		CreatedAt:    finished,
		UpdatedAt:    finished,
	}).Error; err != nil {
		t.Fatalf("seed opted-out row: %v", err)
	}

	if err := core.HealMissingTerminalStats(ctx); err != nil {
		t.Fatalf("HealMissingTerminalStats: %v", err)
	}

	if count := countStatsRaw(t, core); count != 1 {
		t.Fatalf("stats_raw count = %d, want 1 (only the opted-in gap healed)", count)
	}

	got, err := core.GetTestRun(ctx, "run-heal-gap")
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.StatsWrittenAt == nil {
		t.Fatal("stats_written_at = nil after heal, want stamped")
	}

	// A second heal is a no-op for counting: the marker is no longer NULL.
	if err := core.HealMissingTerminalStats(ctx); err != nil {
		t.Fatalf("second HealMissingTerminalStats: %v", err)
	}

	if count := countStatsRaw(t, core); count != 1 {
		t.Fatalf("stats_raw count after second heal = %d, want 1", count)
	}
}

func TestSweepStalledActiveSessions_ReverseShareWaitFlipsToTimeout(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	runID := "run-sweep-reverse-wait"
	stale := staleActiveTimestamp(t, core)

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        StateReverseAwaitingShare,
		SessionKind:  SessionKindActiveFull,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		CreatedAt:    stale,
		UpdatedAt:    stale,
	}).Error; err != nil {
		t.Fatalf("seed stalled reverse wait: %v", err)
	}

	if err := core.SweepStalledActiveSessions(ctx); err != nil {
		t.Fatalf("SweepStalledActiveSessions: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateInterrupted {
		t.Fatalf("state = %q, want %q", got.State, StateInterrupted)
	}

	if got.TerminalReason == nil || *got.TerminalReason != ReasonReverseShareTimeout {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, ReasonReverseShareTimeout)
	}

	// The timeout interruption is the one interruption a late reverse share
	// may still recover.
	passed, err := core.FlipLateReverseShareToPass(ctx, runID)
	if err != nil {
		t.Fatalf("FlipLateReverseShareToPass: %v", err)
	}

	if !passed {
		t.Fatal("passed = false, want the timeout-interrupted wait to flip")
	}
}

func TestSweepStalledActiveSessions_CapabilityExerciseStallStaysUnflippable(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	runID := "run-sweep-capability"
	stale := staleActiveTimestamp(t, core)

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        StateCapabilityExercise,
		SessionKind:  SessionKindActiveFull,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		CreatedAt:    stale,
		UpdatedAt:    stale,
	}).Error; err != nil {
		t.Fatalf("seed stalled capability exercise: %v", err)
	}

	if err := core.SweepStalledActiveSessions(ctx); err != nil {
		t.Fatalf("SweepStalledActiveSessions: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateInterrupted {
		t.Fatalf("state = %q, want %q", got.State, StateInterrupted)
	}

	if got.TerminalReason == nil || *got.TerminalReason != "stall_inactivity_expired" {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, "stall_inactivity_expired")
	}

	passed, err := core.FlipLateReverseShareToPass(ctx, runID)
	if err != nil {
		t.Fatalf("FlipLateReverseShareToPass: %v", err)
	}

	if passed {
		t.Fatal("passed = true, want the inactivity interruption to stay unflippable")
	}
}
