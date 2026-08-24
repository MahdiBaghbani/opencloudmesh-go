// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func terminalPassUpdate() ActiveTerminalUpdate {
	grade := GradePass

	return ActiveTerminalUpdate{
		State:          StateTerminalPass,
		TerminalReason: ReasonReverseShareObserved,
		OverallGrade:   &grade,
	}
}

func TestReleaseActiveTerminal_SealForeverTierKeepsExpiresAtNull(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-seal-forever"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)
	optRunIntoPermanent(t, core, runID, RetentionTierForever)

	preset := time.Now().Unix() + 3600
	if err := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		Updates(map[string]any{colExpiresAt: preset}).Error; err != nil {
		t.Fatalf("preset expires_at: %v", err)
	}

	if err := core.ReleaseActiveTerminal(ctx, runID, StateCapabilityExercise, terminalPassUpdate()); err != nil {
		t.Fatalf("ReleaseActiveTerminal: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.ExpiresAt != nil {
		t.Fatalf("expires_at = %v, want NULL for forever tier", got.ExpiresAt)
	}
}

func TestReleaseActiveTerminal_SealFiniteTierUsesFinishedAt(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-seal-finite"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)
	optRunIntoPermanent(t, core, runID, RetentionTier7)

	if err := core.ReleaseActiveTerminal(ctx, runID, StateCapabilityExercise, terminalPassUpdate()); err != nil {
		t.Fatalf("ReleaseActiveTerminal: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.FinishedAt == nil {
		t.Fatal("finished_at = nil, want stamped")
	}

	days, forever, ok := RetentionTierDays(RetentionTier7)
	if !ok || forever {
		t.Fatalf("RetentionTierDays(%q) = (%d, %v, %v), want finite", RetentionTier7, days, forever, ok)
	}

	want := *got.FinishedAt + int64(days)*SecondsPerDay
	if got.ExpiresAt == nil || *got.ExpiresAt != want {
		t.Fatalf("expires_at = %v, want %d (finished_at + tier days)", got.ExpiresAt, want)
	}
}

func TestReleaseActiveTerminal_SealFiniteTierAnchorsToPreservedFinishedAt(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-seal-preserved-finished"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)
	optRunIntoPermanent(t, core, runID, RetentionTier7)

	preserved := time.Now().Unix() - 600
	if err := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		Updates(map[string]any{colFinishedAt: preserved}).Error; err != nil {
		t.Fatalf("backfill finished_at: %v", err)
	}

	if err := core.ReleaseActiveTerminal(ctx, runID, StateCapabilityExercise, terminalPassUpdate()); err != nil {
		t.Fatalf("ReleaseActiveTerminal: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive {
		t.Fatal("is_active = 1, want 0")
	}

	if got.State != StateTerminalPass {
		t.Fatalf("state = %q, want %q", got.State, StateTerminalPass)
	}

	if got.FinishedAt == nil || *got.FinishedAt != preserved {
		t.Fatalf("finished_at = %v, want preserved %d", got.FinishedAt, preserved)
	}

	days, forever, ok := RetentionTierDays(RetentionTier7)
	if !ok || forever {
		t.Fatalf("RetentionTierDays(%q) = (%d, %v, %v), want finite", RetentionTier7, days, forever, ok)
	}

	want := preserved + int64(days)*SecondsPerDay
	if got.ExpiresAt == nil || *got.ExpiresAt != want {
		t.Fatalf("expires_at = %v, want %d (preserved finished_at + tier days)", got.ExpiresAt, want)
	}
}

func TestReleaseActiveTerminal_SealInvalidTierFallsBackToDefault(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-seal-invalid-tier"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)
	optRunIntoPermanent(t, core, runID, "bogus")

	if err := core.ReleaseActiveTerminal(ctx, runID, StateCapabilityExercise, terminalPassUpdate()); err != nil {
		t.Fatalf("ReleaseActiveTerminal: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.FinishedAt == nil {
		t.Fatal("finished_at = nil, want stamped")
	}

	days, forever, ok := RetentionTierDays(DefaultRetentionTier)
	if !ok || forever {
		t.Fatalf("RetentionTierDays(%q) = (%d, %v, %v), want finite", DefaultRetentionTier, days, forever, ok)
	}

	want := *got.FinishedAt + int64(days)*SecondsPerDay
	if got.ExpiresAt == nil || *got.ExpiresAt != want {
		t.Fatalf("expires_at = %v, want %d (finished_at + default tier days)", got.ExpiresAt, want)
	}
}

func TestReleaseActiveTerminal_SealDefaultsTierWhenMissing(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-seal-default"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)

	if err := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		Updates(map[string]any{"opt_in_permanent": true}).Error; err != nil {
		t.Fatalf("opt into permanent: %v", err)
	}

	if err := core.ReleaseActiveTerminal(ctx, runID, StateCapabilityExercise, terminalPassUpdate()); err != nil {
		t.Fatalf("ReleaseActiveTerminal: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.FinishedAt == nil {
		t.Fatal("finished_at = nil, want stamped")
	}

	days, forever, ok := RetentionTierDays(DefaultRetentionTier)
	if !ok || forever {
		t.Fatalf("RetentionTierDays(%q) = (%d, %v, %v), want finite", DefaultRetentionTier, days, forever, ok)
	}

	want := *got.FinishedAt + int64(days)*SecondsPerDay
	if got.ExpiresAt == nil || *got.ExpiresAt != want {
		t.Fatalf("expires_at = %v, want %d (finished_at + default tier days)", got.ExpiresAt, want)
	}
}

func TestReleaseActiveTerminal_DoesNotSealNonPermanentRow(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-seal-nonpermanent"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)

	if err := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		Updates(map[string]any{colRetentionTier: RetentionTier7}).Error; err != nil {
		t.Fatalf("seed retention tier: %v", err)
	}

	if err := core.ReleaseActiveTerminal(ctx, runID, StateCapabilityExercise, terminalPassUpdate()); err != nil {
		t.Fatalf("ReleaseActiveTerminal: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive {
		t.Fatal("is_active = 1, want 0")
	}

	if got.ExpiresAt != nil {
		t.Fatalf("expires_at = %v, want nil for a non-permanent row", got.ExpiresAt)
	}
}
