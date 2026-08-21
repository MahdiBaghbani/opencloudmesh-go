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

func seedActiveRunInState(t *testing.T, core *Core, runID, state string) {
	t.Helper()

	now := time.Now().Unix()

	if err := core.DB().WithContext(t.Context()).Create(&TestRun{
		TestRunID:  runID,
		IsActive:   true,
		State:      state,
		TargetHost: "release.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}).Error; err != nil {
		t.Fatalf("seed active run %s: %v", runID, err)
	}
}

func optRunIntoPermanent(t *testing.T, core *Core, runID string, tier string) {
	t.Helper()

	if err := core.DB().WithContext(t.Context()).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		Updates(map[string]any{
			"opt_in_permanent": true,
			colRetentionTier:   tier,
		}).Error; err != nil {
		t.Fatalf("opt %s into permanent retention: %v", runID, err)
	}
}

func TestReleaseActiveTerminal_WritesTerminalFieldsAtomically(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-release-pass"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)

	grade := GradePass
	before := time.Now().Unix()

	if err := core.ReleaseActiveTerminal(ctx, runID, StateCapabilityExercise, ActiveTerminalUpdate{
		State:          StateTerminalPass,
		TerminalReason: "completed",
		OverallGrade:   &grade,
	}); err != nil {
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

	if got.FinishedAt == nil || *got.FinishedAt < before {
		t.Fatalf("finished_at = %v, want a stamp >= %d", got.FinishedAt, before)
	}

	if got.UpdatedAt != *got.FinishedAt {
		t.Fatalf("updated_at = %d, want the finished_at stamp %d", got.UpdatedAt, *got.FinishedAt)
	}

	if got.TerminalReason == nil || *got.TerminalReason != "completed" {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, "completed")
	}

	if got.OverallGrade == nil || *got.OverallGrade != GradePass {
		t.Fatalf("overall_grade = %v, want %q", got.OverallGrade, GradePass)
	}
}

func TestReleaseActiveTerminal_PreservesExistingFinishedAt(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-release-preserve-finished"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)

	original := time.Now().Unix() - 600

	if err := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		Updates(map[string]any{colFinishedAt: original}).Error; err != nil {
		t.Fatalf("backfill finished_at: %v", err)
	}

	before := time.Now().Unix()

	if err := core.ReleaseActiveTerminal(ctx, runID, StateCapabilityExercise, ActiveTerminalUpdate{
		State:          StateTerminalFail,
		TerminalReason: "stall_timeout",
	}); err != nil {
		t.Fatalf("ReleaseActiveTerminal: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive {
		t.Fatal("is_active = 1, want 0")
	}

	if got.State != StateTerminalFail {
		t.Fatalf("state = %q, want %q", got.State, StateTerminalFail)
	}

	if got.FinishedAt == nil || *got.FinishedAt != original {
		t.Fatalf("finished_at = %v, want preserved %d", got.FinishedAt, original)
	}

	if got.UpdatedAt < before {
		t.Fatalf("updated_at = %d, want a fresh stamp >= %d", got.UpdatedAt, before)
	}

	if got.TerminalReason == nil || *got.TerminalReason != "stall_timeout" {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, "stall_timeout")
	}
}

func TestReleaseActiveTerminal_InterruptedCarriesNoGrade(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-release-interrupted"

	seedActiveRunInState(t, core, runID, StateActiveRunning)

	if err := core.ReleaseActiveTerminal(ctx, runID, StateActiveRunning, ActiveTerminalUpdate{
		State:          StateInterrupted,
		TerminalReason: "operator_stop",
	}); err != nil {
		t.Fatalf("ReleaseActiveTerminal: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateInterrupted {
		t.Fatalf("state = %q, want %q", got.State, StateInterrupted)
	}

	if got.OverallGrade != nil {
		t.Fatalf("overall_grade = %v, want nil for interrupted", got.OverallGrade)
	}

	if got.FinishedAt == nil {
		t.Fatal("finished_at = nil, want stamped")
	}
}

func TestReleaseActiveTerminalFrom_EmptyExpectedSetRejected(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-release-empty"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)

	update := ActiveTerminalUpdate{
		State:          StateTerminalFail,
		TerminalReason: "stall_timeout",
	}

	err := core.ReleaseActiveTerminalFrom(ctx, runID, []string{}, update)
	if !errors.Is(err, ErrTerminalExpectedStatesEmpty) {
		t.Fatalf("empty set error = %v, want ErrTerminalExpectedStatesEmpty", err)
	}

	err = core.ReleaseActiveTerminalFrom(ctx, runID, nil, update)
	if !errors.Is(err, ErrTerminalExpectedStatesEmpty) {
		t.Fatalf("nil set error = %v, want ErrTerminalExpectedStatesEmpty", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive || got.State != StateCapabilityExercise {
		t.Fatalf("is_active=%v state=%q, want untouched capability_exercise", got.IsActive, got.State)
	}

	if got.FinishedAt != nil {
		t.Fatalf("finished_at = %v, want nil", got.FinishedAt)
	}
}

func TestReleaseActiveTerminalFrom_TerminalExpectedStateRejected(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-release-terminal-set"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)

	err := core.ReleaseActiveTerminalFrom(ctx, runID,
		[]string{StateCapabilityExercise, StateTerminalPass},
		ActiveTerminalUpdate{
			State:          StateTerminalFail,
			TerminalReason: "stall_timeout",
		})
	if !errors.Is(err, ErrTerminalExpectedStatesTerminal) {
		t.Fatalf("error = %v, want ErrTerminalExpectedStatesTerminal", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive || got.State != StateCapabilityExercise {
		t.Fatalf("is_active=%v state=%q, want untouched capability_exercise", got.IsActive, got.State)
	}

	if got.FinishedAt != nil {
		t.Fatalf("finished_at = %v, want nil", got.FinishedAt)
	}
}

func TestReleaseActiveTerminal_NonTerminalTargetRejected(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-release-bad-target"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)

	err := core.ReleaseActiveTerminal(ctx, runID, StateCapabilityExercise, ActiveTerminalUpdate{
		State:          StateActiveRunning,
		TerminalReason: "bogus",
	})
	if !errors.Is(err, ErrTerminalStateInvalid) {
		t.Fatalf("error = %v, want ErrTerminalStateInvalid", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive || got.State != StateCapabilityExercise {
		t.Fatalf("is_active=%v state=%q, want untouched capability_exercise", got.IsActive, got.State)
	}
}

func TestReleaseActiveTerminal_SecondTerminalizationMisses(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-release-twice"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)

	grade := GradePass
	if err := core.ReleaseActiveTerminal(ctx, runID, StateCapabilityExercise, ActiveTerminalUpdate{
		State:          StateTerminalPass,
		TerminalReason: "completed",
		OverallGrade:   &grade,
	}); err != nil {
		t.Fatalf("first release: %v", err)
	}

	first, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after first release: %v", err)
	}

	if first.FinishedAt == nil {
		t.Fatal("finished_at = nil after first release, want stamped")
	}

	err = core.ReleaseActiveTerminal(ctx, runID, StateCapabilityExercise, ActiveTerminalUpdate{
		State:          StateTerminalFail,
		TerminalReason: "second",
	})
	if !errors.Is(err, ErrStateTransitionMiss) {
		t.Fatalf("second release error = %v, want ErrStateTransitionMiss", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after second release: %v", err)
	}

	if got.State != StateTerminalPass {
		t.Fatalf("state = %q, want unchanged %q", got.State, StateTerminalPass)
	}

	if got.FinishedAt == nil || *got.FinishedAt != *first.FinishedAt {
		t.Fatalf("finished_at = %v, want unchanged %d", got.FinishedAt, *first.FinishedAt)
	}

	if got.TerminalReason == nil || *got.TerminalReason != "completed" {
		t.Fatalf("terminal_reason = %v, want unchanged %q", got.TerminalReason, "completed")
	}

	if got.OverallGrade == nil || *got.OverallGrade != GradePass {
		t.Fatalf("overall_grade = %v, want unchanged %q", got.OverallGrade, GradePass)
	}
}
