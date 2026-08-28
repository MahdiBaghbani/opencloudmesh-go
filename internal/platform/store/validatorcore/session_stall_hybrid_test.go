// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func TestSweepStalledActiveSessions_ReleasesTerminalHybridWithoutRewrite(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	now := time.Now().Unix()
	finishedAt := now - 600
	expiresAt := now + 30*SecondsPerDay
	grade := GradePass
	reason := "completed"
	runID := "run-stall-hybrid"

	// A partial terminal write: terminal state and clock fields landed, the
	// active lock and the stats marker did not.
	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      runID,
		IsActive:       true,
		State:          StateTerminalPass,
		TargetOrigin:   "https://peer.example",
		TargetHost:     "peer.example",
		TerminalReason: &reason,
		FinishedAt:     &finishedAt,
		OverallGrade:   &grade,
		ExpiresAt:      &expiresAt,
		OptInStats:     true,
		CreatedAt:      finishedAt,
		UpdatedAt:      finishedAt,
	}).Error; err != nil {
		t.Fatalf("seed hybrid run: %v", err)
	}

	if err := core.SweepStalledActiveSessions(ctx); err != nil {
		t.Fatalf("SweepStalledActiveSessions: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive {
		t.Fatal("is_active = 1, want 0 after hybrid release")
	}

	assertHybridTerminalFields(t, got, finishedAt, reason, grade, expiresAt)

	if got.StatsWrittenAt != nil {
		t.Fatalf("stats_written_at = %v, want nil: hybrid release must not persist stats", got.StatsWrittenAt)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 0 {
		t.Fatalf("stats_raw count = %d, want 0: hybrid release must not persist stats", rawCount)
	}
}

// assertHybridTerminalFields checks that releasing the active lock left the
// terminal state and every terminal clock field exactly as the partial write
// left them.
func assertHybridTerminalFields(
	t *testing.T,
	got *TestRun,
	finishedAt int64,
	reason string,
	grade string,
	expiresAt int64,
) {
	t.Helper()

	if got.State != StateTerminalPass {
		t.Fatalf("state = %q, want unchanged %q", got.State, StateTerminalPass)
	}

	if got.FinishedAt == nil || *got.FinishedAt != finishedAt {
		t.Fatalf("finished_at = %v, want preserved %d", got.FinishedAt, finishedAt)
	}

	if got.TerminalReason == nil || *got.TerminalReason != reason {
		t.Fatalf("terminal_reason = %v, want preserved %q", got.TerminalReason, reason)
	}

	if got.OverallGrade == nil || *got.OverallGrade != grade {
		t.Fatalf("overall_grade = %v, want preserved %q", got.OverallGrade, grade)
	}

	if got.ExpiresAt == nil || *got.ExpiresAt != expiresAt {
		t.Fatalf("expires_at = %v, want preserved %d", got.ExpiresAt, expiresAt)
	}
}

func TestSweepStalledActiveSessions_SealsUnsealedPermanentHybridFromFinishedAt(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	now := time.Now().Unix()
	finishedAt := now - 600
	tier := RetentionTier7
	grade := GradePass
	reason := "completed"
	runID := "run-stall-hybrid-unsealed"

	// A partial terminal write on a finite permanent report: terminal state
	// and finished_at landed, the active lock and the expires_at seal did not.
	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      runID,
		IsActive:       true,
		State:          StateTerminalPass,
		TargetOrigin:   "https://peer.example",
		TargetHost:     "peer.example",
		TerminalReason: &reason,
		FinishedAt:     &finishedAt,
		OverallGrade:   &grade,
		OptInPermanent: true,
		RetentionTier:  &tier,
		CreatedAt:      finishedAt,
		UpdatedAt:      finishedAt,
	}).Error; err != nil {
		t.Fatalf("seed unsealed hybrid run: %v", err)
	}

	if err := core.SweepStalledActiveSessions(ctx); err != nil {
		t.Fatalf("SweepStalledActiveSessions: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive {
		t.Fatal("is_active = 1, want 0 after hybrid release")
	}

	if got.FinishedAt == nil || *got.FinishedAt != finishedAt {
		t.Fatalf("finished_at = %v, want preserved %d", got.FinishedAt, finishedAt)
	}

	days, forever, ok := RetentionTierDays(RetentionTier7)
	if !ok || forever {
		t.Fatalf("RetentionTierDays(%q) = (%d, %v, %v), want finite", RetentionTier7, days, forever, ok)
	}

	want := finishedAt + int64(days)*SecondsPerDay
	if got.ExpiresAt == nil || *got.ExpiresAt != want {
		t.Fatalf("expires_at = %v, want %d (preserved finished_at + tier days)", got.ExpiresAt, want)
	}

	if got.StatsWrittenAt != nil {
		t.Fatalf("stats_written_at = %v, want nil: hybrid release must not persist stats", got.StatsWrittenAt)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 0 {
		t.Fatalf("stats_raw count = %d, want 0: hybrid release must not persist stats", rawCount)
	}
}

func TestSweepStalledActiveSessions_FirstWritesFinishedAtBeforeSealing(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	tier := RetentionTier7
	reason := "completed"
	runID := "run-stall-hybrid-no-finish"
	stale := staleActiveTimestamp(t, core)

	// A thinner partial terminal write: only the terminal state landed, so
	// finished_at and the expires_at seal are both still missing.
	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      runID,
		IsActive:       true,
		State:          StateTerminalPass,
		TargetOrigin:   "https://peer.example",
		TargetHost:     "peer.example",
		TerminalReason: &reason,
		OptInPermanent: true,
		RetentionTier:  &tier,
		CreatedAt:      stale,
		UpdatedAt:      stale,
	}).Error; err != nil {
		t.Fatalf("seed hybrid run without finished_at: %v", err)
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
		t.Fatal("is_active = 1, want 0 after hybrid release")
	}

	if got.FinishedAt == nil || *got.FinishedAt < before {
		t.Fatalf("finished_at = %v, want a first-written stamp >= %d", got.FinishedAt, before)
	}

	days, forever, ok := RetentionTierDays(RetentionTier7)
	if !ok || forever {
		t.Fatalf("RetentionTierDays(%q) = (%d, %v, %v), want finite", RetentionTier7, days, forever, ok)
	}

	want := *got.FinishedAt + int64(days)*SecondsPerDay
	if got.ExpiresAt == nil || *got.ExpiresAt != want {
		t.Fatalf("expires_at = %v, want %d (first-written finished_at + tier days)", got.ExpiresAt, want)
	}
}

func TestSweepStalledActiveSessions_HybridFirstWriteKeepsConcurrentFinishedAt(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	runID := "run-stall-hybrid-race"
	reason := "completed"
	stale := staleActiveTimestamp(t, core)

	// A partial terminal write with finished_at still NULL, as the hybrid
	// selection read would see it.
	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      runID,
		IsActive:       true,
		State:          StateTerminalPass,
		TargetOrigin:   "https://peer.example",
		TargetHost:     "peer.example",
		TerminalReason: &reason,
		CreatedAt:      stale,
		UpdatedAt:      stale,
	}).Error; err != nil {
		t.Fatalf("seed hybrid run without finished_at: %v", err)
	}

	// Between the selection read and the repair transaction, a concurrent
	// writer first-writes finished_at. The repair must not overwrite it with
	// its own later timestamp.
	concurrentFinished := time.Now().Unix() - 5
	if err := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		Update(colFinishedAt, concurrentFinished).Error; err != nil {
		t.Fatalf("concurrent finished_at first-write: %v", err)
	}

	staleSnapshot := TestRun{TestRunID: runID}
	laterNow := time.Now().Unix() + 5

	if err := core.releaseActiveTerminalHybrid(ctx, staleSnapshot, laterNow); err != nil {
		t.Fatalf("releaseActiveTerminalHybrid: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive {
		t.Fatal("is_active = 1, want 0 after hybrid release")
	}

	if got.FinishedAt == nil || *got.FinishedAt != concurrentFinished {
		t.Fatalf("finished_at = %v, want preserved concurrent first-write %d", got.FinishedAt, concurrentFinished)
	}
}
