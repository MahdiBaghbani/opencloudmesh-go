// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestStopPassive_PassWarnAndFailEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		runID      string
		area       string
		severity   string
		wantState  string
		wantGrade  string
		wantReason string
	}{
		{
			name:       "no evidence is pass",
			runID:      "run-stop-pass",
			wantState:  StateTerminalPass,
			wantGrade:  GradePass,
			wantReason: reasonStopped,
		},
		{
			name:       "discovery warn stays pass",
			runID:      "run-stop-discovery-warn",
			area:       SpecificationAreaDiscovery,
			severity:   GradeWarn,
			wantState:  StateTerminalPass,
			wantGrade:  GradeWarn,
			wantReason: reasonStopped,
		},
		{
			name:       "tls warn stays pass",
			runID:      "run-stop-tls-warn",
			area:       SpecificationAreaTLS,
			severity:   GradeWarn,
			wantState:  StateTerminalPass,
			wantGrade:  GradeWarn,
			wantReason: reasonStopped,
		},
		{
			name:       "discovery fail is fail",
			runID:      "run-stop-discovery-fail",
			area:       SpecificationAreaDiscovery,
			severity:   GradeFail,
			wantState:  StateTerminalFail,
			wantGrade:  GradeFail,
			wantReason: reasonProbeFailed,
		},
		{
			name:       "tls fail is fail",
			runID:      "run-stop-tls-fail",
			area:       SpecificationAreaTLS,
			severity:   GradeFail,
			wantState:  StateTerminalFail,
			wantGrade:  GradeFail,
			wantReason: reasonProbeFailed,
		},
		{
			name:       "jwks fail does not block pass",
			runID:      "run-stop-jwks-fail",
			area:       SpecificationAreaJWKS,
			severity:   GradeFail,
			wantState:  StateTerminalPass,
			wantGrade:  GradePass,
			wantReason: reasonStopped,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			runID := tt.runID

			seedPassiveComplete(t, core, runID, "https://peer.example", false)

			if tt.area != "" {
				seedGradedEvidence(t, core, runID, tt.area, tt.severity)
			}

			if err := core.StopPassive(ctx, runID); err != nil {
				t.Fatalf("StopPassive: %v", err)
			}

			got, err := core.GetTestRun(ctx, runID)
			if err != nil {
				t.Fatalf("GetTestRun: %v", err)
			}

			if got.State != tt.wantState {
				t.Fatalf("state = %q, want %q", got.State, tt.wantState)
			}

			if got.OverallGrade == nil || *got.OverallGrade != tt.wantGrade {
				t.Fatalf("overall_grade = %v, want %q", got.OverallGrade, tt.wantGrade)
			}

			if got.TerminalReason == nil || *got.TerminalReason != tt.wantReason {
				t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, tt.wantReason)
			}
		})
	}
}

func TestStopPassive_AlreadyTerminalIsIdempotent(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-stop-already"
	reason := "already-done"
	grade := GradeFail

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      runID,
		State:          StateTerminalFail,
		TargetHost:     "peer.example",
		TerminalReason: &reason,
		OverallGrade:   &grade,
		FinishedAt:     &now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := core.StopPassive(ctx, runID); err != nil {
		t.Fatalf("StopPassive: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateTerminalFail {
		t.Fatalf("state = %q, want unchanged terminal_fail", got.State)
	}

	if got.TerminalReason == nil || *got.TerminalReason != reason {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, reason)
	}
}

func TestFlipLateReverseShareToPass_BypassesWriteTerminal(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	runID := "run-flip-not-write-terminal"
	seedInterruptedRun(t, core, runID, ReasonReverseShareTimeout, true)

	grade := GradePass

	writeErr := core.WriteTerminal(ctx, runID, false, []string{StateInterrupted}, ActiveTerminalUpdate{
		State:          StateTerminalPass,
		TerminalReason: ReasonLateReverseShare,
		OverallGrade:   &grade,
	})
	if !errors.Is(writeErr, ErrTerminalExpectedStatesTerminal) {
		t.Fatalf("WriteTerminal error = %v, want ErrTerminalExpectedStatesTerminal", writeErr)
	}

	passed, err := core.FlipLateReverseShareToPass(ctx, runID)
	if err != nil {
		t.Fatalf("FlipLateReverseShareToPass: %v", err)
	}

	if !passed {
		t.Fatal("late flip must still rewrite timeout-interrupted rows")
	}

	got, getErr := core.GetTestRun(ctx, runID)
	if getErr != nil {
		t.Fatalf("GetTestRun: %v", getErr)
	}

	if got.State != StateTerminalPass {
		t.Fatalf("state = %q, want %q", got.State, StateTerminalPass)
	}
}

func TestWriteTerminal_RejectsTerminalExpectedState(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	grade := GradePass

	err := core.WriteTerminal(
		t.Context(),
		"run-write-reject",
		false,
		[]string{StateInterrupted},
		ActiveTerminalUpdate{
			State:          StateTerminalPass,
			TerminalReason: reasonStopped,
			OverallGrade:   &grade,
		},
	)
	if !errors.Is(err, ErrTerminalExpectedStatesTerminal) {
		t.Fatalf("WriteTerminal error = %v, want ErrTerminalExpectedStatesTerminal", err)
	}
}

func TestWriteTerminal_MissesActiveHybrid(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-hybrid-miss"
	reason := "completed"
	grade := GradePass

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      runID,
		IsActive:       true,
		State:          StateTerminalPass,
		TargetHost:     "hybrid.example",
		TerminalReason: &reason,
		OverallGrade:   &grade,
		FinishedAt:     &now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed hybrid: %v", err)
	}

	err := core.WriteTerminal(ctx, runID, true, []string{StateCapabilityExercise}, ActiveTerminalUpdate{
		State:          StateTerminalFail,
		TerminalReason: "should-not-land",
		OverallGrade:   &grade,
	})
	if !errors.Is(err, ErrStateTransitionMiss) {
		t.Fatalf("WriteTerminal error = %v, want ErrStateTransitionMiss", err)
	}

	got, getErr := core.GetTestRun(ctx, runID)
	if getErr != nil {
		t.Fatalf("GetTestRun: %v", getErr)
	}

	if !got.IsActive {
		t.Fatal("is_active cleared; hybrid lock repair must stay a separate path")
	}

	if got.State != StateTerminalPass {
		t.Fatalf("state = %q, want unchanged terminal_pass", got.State)
	}
}

func TestIsTerminalState_IncludesInterrupted(t *testing.T) {
	t.Parallel()

	if !IsTerminalState(StateInterrupted) {
		t.Fatal("interrupted must stay in IsTerminalState")
	}

	if !slices.Contains(terminalStateSet(), StateInterrupted) {
		t.Fatal("interrupted must stay in terminalStateSet")
	}

	if isPrunableTerminalState(StateInterrupted) {
		t.Fatal("interrupted must stay out of the prune set")
	}

	if slices.Contains(prunableTerminalStateSet(), StateInterrupted) {
		t.Fatal("interrupted must stay out of prunableTerminalStateSet")
	}
}

func TestSweepPassiveCompleteTTL_UsesSharedWriter(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.sessionCfg = SessionConfig{
		InFlightPassiveLimit:      10,
		PassiveCompleteTTLSeconds: 60,
	}

	ctx := t.Context()
	stale := time.Now().Add(-2 * time.Minute).Unix()
	runID := "run-ttl-shared"

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:  runID,
		IsActive:   false,
		State:      StatePassiveComplete,
		TargetHost: "ttl.example",
		CreatedAt:  stale,
		UpdatedAt:  stale,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := core.sweepPassiveCompleteTTL(ctx); err != nil {
		t.Fatalf("sweepPassiveCompleteTTL: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateTerminalFail {
		t.Fatalf("state = %q, want %q", got.State, StateTerminalFail)
	}

	if got.OverallGrade == nil || *got.OverallGrade != GradeFail {
		t.Fatalf("overall_grade = %v, want %q from shared writer", got.OverallGrade, GradeFail)
	}

	if got.FinishedAt == nil {
		t.Fatal("finished_at unset")
	}
}

func TestPassActiveFrom_WritesTerminalPass(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-pass-active"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)

	if err := core.PassActiveFrom(ctx, runID, ActivePassExpectedStates(), "reverse_share_observed"); err != nil {
		t.Fatalf("PassActiveFrom: %v", err)
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

	if got.OverallGrade == nil || *got.OverallGrade != GradePass {
		t.Fatalf("overall_grade = %v, want %q", got.OverallGrade, GradePass)
	}
}

func seedGradedEvidence(t *testing.T, core *Core, runID, area, severity string) {
	t.Helper()

	err := core.ApplyEvidenceFact(t.Context(), ApplyEvidenceFactInput{
		TestRunID:    runID,
		Area:         area,
		Step:         "probe",
		ReasonCode:   "probed",
		Severity:     severity,
		AffectsGrade: true,
		Leg:          evidenceLegPassive,
	})
	if err != nil {
		t.Fatalf("ApplyEvidenceFact: %v", err)
	}
}
