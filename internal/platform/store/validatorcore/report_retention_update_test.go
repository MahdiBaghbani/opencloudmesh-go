// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func TestUpdatePublicReportRetention_ZeroRowsWhenMissingOrPrivate(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	tier := RetentionTier7
	write := ReportRetentionWrite{
		RetentionTier:  &tier,
		UpdatedAt:      now,
		ClearExpiresAt: true,
	}

	affected, err := core.UpdatePublicReportRetention(ctx, "missing-run", now, write)
	if err != nil {
		t.Fatalf("missing update: %v", err)
	}

	if affected != 0 {
		t.Fatalf("missing RowsAffected = %d, want 0", affected)
	}

	if seedErr := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      "run-private",
		State:          StateTerminalPass,
		TargetHost:     "peer.example",
		OptInPermanent: false,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; seedErr != nil {
		t.Fatalf("seed private: %v", seedErr)
	}

	affected, err = core.UpdatePublicReportRetention(ctx, "run-private", now, write)
	if err != nil {
		t.Fatalf("private update: %v", err)
	}

	if affected != 0 {
		t.Fatalf("private RowsAffected = %d, want 0", affected)
	}
}

func TestUpdatePublicReportRetention_UpdatesPublicRow(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	finished := now - 10
	runID := "run-public-retention"

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      runID,
		State:          StateTerminalPass,
		TargetHost:     "peer.example",
		OptInPermanent: true,
		FinishedAt:     &finished,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed public: %v", err)
	}

	tier := RetentionTier14
	expires := finished + int64(14)*SecondsPerDay

	affected, err := core.UpdatePublicReportRetention(ctx, runID, now, ReportRetentionWrite{
		RetentionTier: &tier,
		ExpiresAt:     &expires,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	if affected != 1 {
		t.Fatalf("RowsAffected = %d, want 1", affected)
	}

	row, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.RetentionTier == nil || *row.RetentionTier != tier {
		t.Fatalf("retention_tier = %v, want %q", row.RetentionTier, tier)
	}

	if row.ExpiresAt == nil || *row.ExpiresAt != expires {
		t.Fatalf("expires_at = %v, want %d", row.ExpiresAt, expires)
	}
}

func TestUpdatePublicReportRetention_RequireUnlockedMissesLockedRow(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	finished := now - 10
	runID := "run-locked-retention"
	lockedAt := now
	tier := RetentionTier30

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:         runID,
		State:             StateTerminalPass,
		TargetHost:        "peer.example",
		OptInPermanent:    true,
		FinishedAt:        &finished,
		RetentionTier:     &tier,
		RetentionLockedAt: &lockedAt,
		CreatedAt:         now,
		UpdatedAt:         now,
	}).Error; err != nil {
		t.Fatalf("seed locked: %v", err)
	}

	nextTier := RetentionTier90

	affected, err := core.UpdatePublicReportRetention(ctx, runID, now, ReportRetentionWrite{
		RetentionTier:   &nextTier,
		UpdatedAt:       now,
		RequireUnlocked: true,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	if affected != 0 {
		t.Fatalf("RowsAffected = %d, want 0", affected)
	}

	row, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.RetentionTier == nil || *row.RetentionTier != tier {
		t.Fatalf("retention_tier = %v, want %q", row.RetentionTier, tier)
	}
}

func TestLockPublicReportRetention_SetsLockWithoutTouchingExpires(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	finished := now - 10
	runID := "run-lock-cas"
	tier := RetentionTier90
	expires := finished + int64(90)*SecondsPerDay

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      runID,
		State:          StateTerminalPass,
		TargetHost:     "peer.example",
		OptInPermanent: true,
		FinishedAt:     &finished,
		RetentionTier:  &tier,
		ExpiresAt:      &expires,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	affected, err := core.LockPublicReportRetention(ctx, runID, now)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}

	if affected != 1 {
		t.Fatalf("RowsAffected = %d, want 1", affected)
	}

	row, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.RetentionLockedAt == nil || *row.RetentionLockedAt != now {
		t.Fatalf("retention_locked_at = %v, want %d", row.RetentionLockedAt, now)
	}

	if row.RetentionTier == nil || *row.RetentionTier != tier {
		t.Fatalf("retention_tier = %v, want %q", row.RetentionTier, tier)
	}

	if row.ExpiresAt == nil || *row.ExpiresAt != expires {
		t.Fatalf("expires_at = %v, want %d", row.ExpiresAt, expires)
	}
}

func TestLockPublicReportRetention_AlreadyLockedAffectsZeroRows(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	finished := now - 10
	runID := "run-lock-already"
	tier := RetentionTier90
	expires := finished + int64(90)*SecondsPerDay
	lockedAt := now - 5

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:         runID,
		State:             StateTerminalPass,
		TargetHost:        "peer.example",
		OptInPermanent:    true,
		FinishedAt:        &finished,
		RetentionTier:     &tier,
		RetentionLockedAt: &lockedAt,
		ExpiresAt:         &expires,
		CreatedAt:         now,
		UpdatedAt:         now,
	}).Error; err != nil {
		t.Fatalf("seed locked: %v", err)
	}

	affected, err := core.LockPublicReportRetention(ctx, runID, now)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}

	if affected != 0 {
		t.Fatalf("RowsAffected = %d, want 0", affected)
	}

	row, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.RetentionLockedAt == nil || *row.RetentionLockedAt != lockedAt {
		t.Fatalf("retention_locked_at = %v, want %d", row.RetentionLockedAt, lockedAt)
	}

	if row.ExpiresAt == nil || *row.ExpiresAt != expires {
		t.Fatalf("expires_at = %v, want %d", row.ExpiresAt, expires)
	}
}

func TestLockPublicReportRetention_DefaultsNullTier(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	finished := now - 10
	runID := "run-lock-default-tier"

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      runID,
		State:          StateTerminalPass,
		TargetHost:     "peer.example",
		OptInPermanent: true,
		FinishedAt:     &finished,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	affected, err := core.LockPublicReportRetention(ctx, runID, now)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}

	if affected != 1 {
		t.Fatalf("RowsAffected = %d, want 1", affected)
	}

	row, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.RetentionTier == nil || *row.RetentionTier != DefaultRetentionTier {
		t.Fatalf("retention_tier = %v, want %q", row.RetentionTier, DefaultRetentionTier)
	}

	if row.ExpiresAt != nil {
		t.Fatalf("expires_at = %v, want nil", row.ExpiresAt)
	}
}
