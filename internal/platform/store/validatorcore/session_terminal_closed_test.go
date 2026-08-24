// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	closedWrapperFailPassive   = "fail_passive"
	closedWrapperReleaseActive = "release_active"
)

func TestClosedTerminalReasonRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		runID   string
		wrapper string
		dest    string
		reason  string
		wantErr error
	}{
		{
			name:    "fail rejects typo of legal token",
			runID:   "run-closed-fail-typo",
			wrapper: closedWrapperFailPassive,
			dest:    StateTerminalFail,
			reason:  "passive_probe_failed_typo",
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "fail rejects empty reason",
			runID:   "run-closed-fail-empty",
			wrapper: closedWrapperFailPassive,
			dest:    StateTerminalFail,
			reason:  "",
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "fail rejects interrupted-only reason",
			runID:   "run-closed-fail-timeout",
			wrapper: closedWrapperFailPassive,
			dest:    StateTerminalFail,
			reason:  ReasonReverseShareTimeout,
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "fail rejects pass token",
			runID:   "run-closed-fail-stopped",
			wrapper: closedWrapperFailPassive,
			dest:    StateTerminalFail,
			reason:  ReasonStopped,
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "fail rejects whitespace reason",
			runID:   "run-closed-fail-whitespace",
			wrapper: closedWrapperFailPassive,
			dest:    StateTerminalFail,
			reason:  "   ",
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "interrupted rejects fail token",
			runID:   "run-closed-interrupted-hard-fail",
			wrapper: closedWrapperReleaseActive,
			dest:    StateInterrupted,
			reason:  ReasonActiveHardFail,
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "interrupted rejects empty reason",
			runID:   "run-closed-interrupted-empty",
			wrapper: closedWrapperReleaseActive,
			dest:    StateInterrupted,
			reason:  "",
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "interrupted rejects pass token",
			runID:   "run-closed-interrupted-stopped",
			wrapper: closedWrapperReleaseActive,
			dest:    StateInterrupted,
			reason:  ReasonStopped,
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "pass rejects fail token",
			runID:   "run-closed-pass-hard-fail",
			wrapper: closedWrapperReleaseActive,
			dest:    StateTerminalPass,
			reason:  ReasonActiveHardFail,
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "pass rejects interrupted token",
			runID:   "run-closed-pass-timeout",
			wrapper: closedWrapperReleaseActive,
			dest:    StateTerminalPass,
			reason:  ReasonReverseShareTimeout,
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "pass rejects empty reason",
			runID:   "run-closed-pass-empty",
			wrapper: closedWrapperReleaseActive,
			dest:    StateTerminalPass,
			reason:  "",
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "non-terminal destination is invalid",
			runID:   "run-closed-created-dest",
			wrapper: closedWrapperReleaseActive,
			dest:    StateCreated,
			reason:  ReasonActiveHardFail,
			wantErr: ErrTerminalStateInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()

			seedClosedRejectRow(t, core, tt.runID, tt.wrapper)

			before, err := core.GetTestRun(ctx, tt.runID)
			if err != nil {
				t.Fatalf("GetTestRun before: %v", err)
			}

			gotErr := callClosedRejectWrapper(t, core, tt.runID, tt.wrapper, tt.dest, tt.reason)
			if !errors.Is(gotErr, tt.wantErr) {
				t.Fatalf("error = %v, want %v", gotErr, tt.wantErr)
			}

			// Non-terminal destinations are rejected by validateActiveTerminalRelease
			// before writeTerminalGuarded, so the sentinel stays bare.
			if errors.Is(tt.wantErr, ErrTerminalStateInvalid) && errors.Unwrap(gotErr) != nil {
				t.Fatalf("error = %v, want bare %v", gotErr, tt.wantErr)
			}

			if errors.Is(tt.wantErr, ErrTerminalReasonInvalid) && errors.Unwrap(gotErr) == nil {
				t.Fatalf("error = %v, want wrapped %v", gotErr, tt.wantErr)
			}

			after, err := core.GetTestRun(ctx, tt.runID)
			if err != nil {
				t.Fatalf("GetTestRun after: %v", err)
			}

			assertTerminalRowUnchanged(t, before, after)
		})
	}
}

func TestWriteTerminalGuarded_StoreConfigPrecedesReasonValidation(t *testing.T) {
	t.Parallel()

	// A nil store must fail as unconfigured before an out-of-set reason is checked.
	c := &Core{}

	err := c.writeTerminalGuarded(
		t.Context(),
		"run-store-config-precedes-reason",
		false,
		terminalStateOpIn,
		[]string{StatePassiveRunning},
		ActiveTerminalUpdate{
			State:          StateTerminalFail,
			TerminalReason: "definitely_not_in_set",
		},
	)
	if err == nil {
		t.Fatal("error = nil, want store-config error")
	}

	if errors.Is(err, ErrTerminalReasonInvalid) {
		t.Fatalf("error = %v, must not be ErrTerminalReasonInvalid", err)
	}

	if !strings.Contains(err.Error(), "store is not configured") {
		t.Fatalf("error = %q, want store is not configured", err)
	}
}

func TestFailPassive_EmptyReasonRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		runID string
		state string
	}{
		{
			name:  "passive_running stays non-terminal",
			runID: "run-fail-passive-empty",
			state: StatePassiveRunning,
		},
		{
			name:  "created stays non-terminal",
			runID: "run-fail-passive-empty-created",
			state: StateCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()

			seedInactiveRow(t, core, tt.runID, tt.state)

			before, err := core.GetTestRun(ctx, tt.runID)
			if err != nil {
				t.Fatalf("GetTestRun before: %v", err)
			}

			gotErr := core.FailPassive(ctx, tt.runID, tt.state, "")
			if !errors.Is(gotErr, ErrTerminalReasonInvalid) {
				t.Fatalf("FailPassive empty reason = %v, want ErrTerminalReasonInvalid", gotErr)
			}

			if errors.Is(gotErr, ErrTerminalReasonInvalid) && errors.Unwrap(gotErr) == nil {
				t.Fatalf("error = %v, want wrapped %v", gotErr, ErrTerminalReasonInvalid)
			}

			after, err := core.GetTestRun(ctx, tt.runID)
			if err != nil {
				t.Fatalf("GetTestRun after: %v", err)
			}

			if after.State != tt.state {
				t.Fatalf("state = %q, want %q", after.State, tt.state)
			}

			if isTerminalState(after.State) {
				t.Fatalf("state = %q, want a non-terminal %s row", after.State, tt.state)
			}

			assertTerminalRowUnchanged(t, before, after)
		})
	}
}

func TestClosedTerminalReasonAccepted(t *testing.T) {
	t.Parallel()

	t.Run("fail passive accepts probe failed", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		ctx := t.Context()
		runID := "run-closed-accept-fail-passive"

		seedInactivePassiveRunning(t, core, runID)

		if err := core.FailPassive(ctx, runID, StatePassiveRunning, ReasonPassiveProbeFailed); err != nil {
			t.Fatalf("FailPassive: %v", err)
		}

		assertTerminalized(t, core, runID, StateTerminalFail, ReasonPassiveProbeFailed)
	})

	t.Run("release active accepts hard fail", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		ctx := t.Context()
		runID := "run-closed-accept-hard-fail"

		seedActiveRunInState(t, core, runID, StateCapabilityExercise)

		if err := core.ReleaseActiveTerminal(ctx, runID, StateCapabilityExercise, ActiveTerminalUpdate{
			State:          StateTerminalFail,
			TerminalReason: ReasonActiveHardFail,
		}); err != nil {
			t.Fatalf("ReleaseActiveTerminal: %v", err)
		}

		assertTerminalized(t, core, runID, StateTerminalFail, ReasonActiveHardFail)
	})

	t.Run("flip late reverse share accepts timeout interrupted", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		ctx := t.Context()
		runID := "run-closed-accept-flip"

		seedInterruptedRun(t, core, runID, ReasonReverseShareTimeout, false)

		passed, err := core.FlipLateReverseShareToPass(ctx, runID)
		if err != nil {
			t.Fatalf("FlipLateReverseShareToPass: %v", err)
		}

		if !passed {
			t.Fatal("passed = false, want true")
		}

		assertTerminalized(t, core, runID, StateTerminalPass, ReasonLateReverseShare)
	})

	t.Run("pass active accepts reverse share observed", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		ctx := t.Context()
		runID := "run-closed-accept-observed"

		seedActiveRunInState(t, core, runID, StateCapabilityExercise)

		if err := core.PassActiveFrom(ctx, runID, ActivePassExpectedStates(), ReasonReverseShareObserved); err != nil {
			t.Fatalf("PassActiveFrom: %v", err)
		}

		assertTerminalized(t, core, runID, StateTerminalPass, ReasonReverseShareObserved)
	})
}

func seedClosedRejectRow(t *testing.T, core *Core, runID, wrapper string) {
	t.Helper()

	switch wrapper {
	case closedWrapperFailPassive:
		seedInactivePassiveRunning(t, core, runID)
	case closedWrapperReleaseActive:
		seedActiveRunInState(t, core, runID, StateCapabilityExercise)
	default:
		t.Fatalf("unknown wrapper %q", wrapper)
	}
}

func seedInactivePassiveRunning(t *testing.T, core *Core, runID string) {
	t.Helper()

	seedInactiveRow(t, core, runID, StatePassiveRunning)
}

func seedInactiveRow(t *testing.T, core *Core, runID, state string) {
	t.Helper()

	now := time.Now().Unix()

	if err := core.DB().WithContext(t.Context()).Create(&TestRun{
		TestRunID:  runID,
		IsActive:   false,
		State:      state,
		TargetHost: "closed.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}).Error; err != nil {
		t.Fatalf("seed %s %s: %v", state, runID, err)
	}
}

func callClosedRejectWrapper(
	t *testing.T,
	core *Core,
	runID, wrapper, dest, reason string,
) error {
	t.Helper()

	ctx := t.Context()

	switch wrapper {
	case closedWrapperFailPassive:
		return core.FailPassive(ctx, runID, StatePassiveRunning, reason)
	case closedWrapperReleaseActive:
		return core.ReleaseActiveTerminal(ctx, runID, StateCapabilityExercise, ActiveTerminalUpdate{
			State:          dest,
			TerminalReason: reason,
		})
	default:
		t.Fatalf("unknown wrapper %q", wrapper)

		return nil
	}
}

func assertTerminalRowUnchanged(t *testing.T, before, after *TestRun) {
	t.Helper()

	if after.State != before.State {
		t.Fatalf("state = %q, want unchanged %q", after.State, before.State)
	}

	if !optionalStringEqual(after.TerminalReason, before.TerminalReason) {
		t.Fatalf(
			"terminal_reason = %s, want unchanged %s",
			formatOptionalString(after.TerminalReason),
			formatOptionalString(before.TerminalReason),
		)
	}

	if !optionalInt64Equal(after.FinishedAt, before.FinishedAt) {
		t.Fatalf(
			"finished_at = %s, want unchanged %s",
			formatOptionalInt64(after.FinishedAt),
			formatOptionalInt64(before.FinishedAt),
		)
	}

	if after.IsActive != before.IsActive {
		t.Fatalf("is_active = %v, want unchanged %v", after.IsActive, before.IsActive)
	}

	if !optionalStringEqual(after.OverallGrade, before.OverallGrade) {
		t.Fatalf(
			"overall_grade = %s, want unchanged %s",
			formatOptionalString(after.OverallGrade),
			formatOptionalString(before.OverallGrade),
		)
	}

	if after.UpdatedAt != before.UpdatedAt {
		t.Fatalf("updated_at = %d, want unchanged %d", after.UpdatedAt, before.UpdatedAt)
	}
}

func assertTerminalized(t *testing.T, core *Core, runID, wantState, wantReason string) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive {
		t.Fatal("is_active = 1, want 0")
	}

	if got.State != wantState {
		t.Fatalf("state = %q, want %q", got.State, wantState)
	}

	if got.TerminalReason == nil || *got.TerminalReason != wantReason {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, wantReason)
	}
}

func optionalStringEqual(got, want *string) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}

	return *got == *want
}

func optionalInt64Equal(got, want *int64) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}

	return *got == *want
}

func formatOptionalString(v *string) string {
	if v == nil {
		return "<nil>"
	}

	return *v
}

func formatOptionalInt64(v *int64) string {
	if v == nil {
		return "<nil>"
	}

	return strconv.FormatInt(*v, 10)
}
