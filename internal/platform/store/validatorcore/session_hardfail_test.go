// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm/logger"
)

// allNonTerminalStates derives every non-terminal state the schema permits
// from the session state enum. Covering the full set is the strongest
// name-agnostic proof the schema allows: the state CHECK constraint forbids
// names outside the enum, so an implementation that enumerated only some
// forward names would miss one of these subtests.
func allNonTerminalStates() []string {
	states := make([]string, 0, len(testRunStates))

	for _, state := range testRunStates {
		if !isTerminalState(state) {
			states = append(states, state)
		}
	}

	return states
}

func TestReleaseActiveHardFail_IdentityReasonFailsFromAnyNonTerminalState(t *testing.T) {
	t.Parallel()

	for _, state := range allNonTerminalStates() {
		t.Run(state, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			runID := "run-hardfail-identity-" + state

			seedActiveRunInState(t, core, runID, state)

			before := time.Now().Unix()

			if err := core.ReleaseActiveHardFail(ctx, runID, ReasonActiveHardFailIdentity); err != nil {
				t.Fatalf("ReleaseActiveHardFail from %s: %v", state, err)
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

			if got.TerminalReason == nil || *got.TerminalReason != ReasonActiveHardFailIdentity {
				t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, ReasonActiveHardFailIdentity)
			}

			if got.FinishedAt == nil || *got.FinishedAt < before {
				t.Fatalf("finished_at = %v, want a stamp >= %d", got.FinishedAt, before)
			}
		})
	}
}

func TestReleaseActiveHardFail_NonIdentityReasonRefusedInGradedExerciseStates(t *testing.T) {
	t.Parallel()

	for _, state := range hardFailProtectedStates {
		t.Run(state, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			runID := "run-hardfail-refused-" + state

			seedActiveRunInState(t, core, runID, state)

			err := core.ReleaseActiveHardFail(ctx, runID, ReasonOperatorAborted)
			if !errors.Is(err, ErrActiveHardFailRefused) {
				t.Fatalf("error = %v, want ErrActiveHardFailRefused", err)
			}

			assertActiveInState(t, core, runID, state)
		})
	}
}

func TestReleaseActiveHardFail_NonIdentityReasonFailsFromOtherStates(t *testing.T) {
	t.Parallel()

	states := []string{
		StateActiveRunning,
		StateInviteMinted,
		StateForwardShareSent,
		StateReverseAwaitingInvite,
	}

	for _, state := range states {
		t.Run(state, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			runID := "run-hardfail-other-" + state

			seedActiveRunInState(t, core, runID, state)

			if err := core.ReleaseActiveHardFail(ctx, runID, ReasonOperatorAborted); err != nil {
				t.Fatalf("ReleaseActiveHardFail from %s: %v", state, err)
			}

			got, err := core.GetTestRun(ctx, runID)
			if err != nil {
				t.Fatalf("GetTestRun: %v", err)
			}

			if got.IsActive || got.State != StateTerminalFail {
				t.Fatalf("is_active=%v state=%q, want released terminal_fail", got.IsActive, got.State)
			}

			if got.TerminalReason == nil || *got.TerminalReason != ReasonOperatorAborted {
				t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, ReasonOperatorAborted)
			}
		})
	}
}

func TestReleaseActiveHardFail_MissesTerminalInactiveAndUnknownRows(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()

	terminalID := "run-hardfail-terminal"
	seedActiveRunInState(t, core, terminalID, StateForwardShareSent)

	if err := core.ReleaseActiveHardFail(ctx, terminalID, ReasonOperatorAborted); err != nil {
		t.Fatalf("release %s: %v", terminalID, err)
	}

	// A hybrid row holds the active lock in an already-terminal state; the
	// hard-fail exclusion always contains the terminal states, so the row is
	// a plain miss, never a refusal and never a rewrite.
	hybridID := "run-hardfail-hybrid"
	hybridReason := "completed"

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      hybridID,
		IsActive:       true,
		State:          StateTerminalPass,
		SessionKind:    SessionKindActiveFull,
		TargetHost:     "release.example",
		TerminalReason: &hybridReason,
		FinishedAt:     &now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed hybrid run: %v", err)
	}

	// A passive row carries no active lock; hard-fail only acts on the lock
	// holder.
	passiveID := "run-hardfail-passive"

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:   passiveID,
		IsActive:    false,
		State:       StateCreated,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "release.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}).Error; err != nil {
		t.Fatalf("seed passive run: %v", err)
	}

	for _, runID := range []string{terminalID, hybridID, passiveID, "run-hardfail-unknown"} {
		err := core.ReleaseActiveHardFail(ctx, runID, ReasonOperatorAborted)
		if !errors.Is(err, ErrStateTransitionMiss) {
			t.Fatalf("hard-fail %s error = %v, want ErrStateTransitionMiss", runID, err)
		}

		if errors.Is(err, ErrActiveHardFailRefused) {
			t.Fatalf("hard-fail %s error = %v, must not be a refusal", runID, err)
		}
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

func TestReleaseActiveHardFail_PersistsTerminalStats(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	runID := "run-hardfail-stats"
	now := time.Now().Unix()

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        StateActiveRunning,
		SessionKind:  SessionKindActiveFull,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		OptInStats:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed opted-in active run: %v", err)
	}

	if err := core.ReleaseActiveHardFail(ctx, runID, ReasonOperatorAborted); err != nil {
		t.Fatalf("ReleaseActiveHardFail: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.FinishedAt == nil {
		t.Fatal("finished_at = nil, want a stamp")
	}

	// The stats write requires finished_at, so a persisted stats row proves
	// the state transition committed before statistics persistence ran.
	if got.StatsWrittenAt == nil || *got.StatsWrittenAt < *got.FinishedAt {
		t.Fatalf("stats_written_at = %v, want a stamp >= finished_at %d", got.StatsWrittenAt, *got.FinishedAt)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw count = %d, want 1 after hard-fail", rawCount)
	}
}

func TestReleaseActiveHardFail_ConcurrentForwardCASNoSteal(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-hardfail-race"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)

	conn1, conn2 := acquireTwoSQLConns(t, core)

	observed := observeStateOnConn(t, conn1, runID)
	if observed != StateCapabilityExercise {
		t.Fatalf("observed state = %q, want %q", observed, StateCapabilityExercise)
	}

	// The graded flow advances between the failure signal and the guarded
	// write; the refusal must hold from the post-CAS state too.
	runGuardedCASOnConn(t, conn2, runID, StateCapabilityExercise, StateReverseAwaitingShare)

	err := core.ReleaseActiveHardFail(ctx, runID, ReasonOperatorAborted)
	if !errors.Is(err, ErrActiveHardFailRefused) {
		t.Fatalf("hard-fail error = %v, want ErrActiveHardFailRefused", err)
	}

	assertActiveInState(t, core, runID, StateReverseAwaitingShare)

	// The identity reason may still interrupt from the post-CAS state.
	if identityErr := core.ReleaseActiveHardFail(ctx, runID, ReasonActiveHardFailIdentity); identityErr != nil {
		t.Fatalf("identity hard-fail from CAS post-state: %v", identityErr)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive || got.State != StateTerminalFail {
		t.Fatalf("is_active=%v state=%q, want released terminal_fail", got.IsActive, got.State)
	}
}

func TestReleaseActiveHardFail_EmitsNameAgnosticNotInGuard(t *testing.T) {
	t.Parallel()

	t.Run("identity excludes only the terminal states", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		ctx := t.Context()
		runID := "run-hardfail-sql-identity"

		seedActiveRunInState(t, core, runID, StateActiveRunning)

		recorder := &sqlStatementLogger{}
		core.DB().Logger = recorder

		if err := core.ReleaseActiveHardFail(ctx, runID, ReasonActiveHardFailIdentity); err != nil {
			t.Fatalf("ReleaseActiveHardFail: %v", err)
		}

		stmt := recorder.guardedStateUpdate(t)

		if !strings.Contains(stmt, "state NOT IN") {
			t.Fatalf("guarded UPDATE = %q, want a name-agnostic state NOT IN guard", stmt)
		}

		for _, terminal := range []string{StateTerminalPass, StateTerminalFail, StateInterrupted} {
			if !strings.Contains(stmt, terminal) {
				t.Fatalf("guarded UPDATE = %q, want %q in the exclusion list", stmt, terminal)
			}
		}

		for _, protected := range hardFailProtectedStates {
			if strings.Contains(stmt, protected) {
				t.Fatalf("guarded UPDATE = %q, identity reason must not exclude %q", stmt, protected)
			}
		}
	})

	t.Run("non-identity adds the graded exercise exclusions", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		ctx := t.Context()
		runID := "run-hardfail-sql-operator"

		seedActiveRunInState(t, core, runID, StateActiveRunning)

		recorder := &sqlStatementLogger{}
		core.DB().Logger = recorder

		if err := core.ReleaseActiveHardFail(ctx, runID, ReasonOperatorAborted); err != nil {
			t.Fatalf("ReleaseActiveHardFail: %v", err)
		}

		stmt := recorder.guardedStateUpdate(t)

		if !strings.Contains(stmt, "state NOT IN") {
			t.Fatalf("guarded UPDATE = %q, want a name-agnostic state NOT IN guard", stmt)
		}

		for _, excluded := range []string{
			StateTerminalPass,
			StateTerminalFail,
			StateInterrupted,
			StateCapabilityExercise,
			StateReverseAwaitingShare,
		} {
			if !strings.Contains(stmt, excluded) {
				t.Fatalf("guarded UPDATE = %q, want %q in the exclusion list", stmt, excluded)
			}
		}
	})
}

// sqlStatementLogger records every explained SQL statement gorm emits, so a
// test can assert the exact guard shape of the shared terminal writer.
type sqlStatementLogger struct {
	mu         sync.Mutex
	statements []string
}

func (l *sqlStatementLogger) LogMode(logger.LogLevel) logger.Interface { return l }

func (l *sqlStatementLogger) Info(context.Context, string, ...any) {}

func (l *sqlStatementLogger) Warn(context.Context, string, ...any) {}

func (l *sqlStatementLogger) Error(context.Context, string, ...any) {}

func (l *sqlStatementLogger) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	sql, _ := fc()

	l.mu.Lock()
	l.statements = append(l.statements, sql)
	l.mu.Unlock()
}

// guardedStateUpdate returns the captured statement carrying the state guard.
// The explained SQL interpolates the exclusion values, so the guard shape and
// the exact excluded state names are both visible.
func (l *sqlStatementLogger) guardedStateUpdate(t *testing.T) string {
	t.Helper()

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, sql := range l.statements {
		if strings.Contains(sql, "state NOT IN") || strings.Contains(sql, "state IN") {
			return sql
		}
	}

	t.Fatal("no guarded state UPDATE captured")

	return ""
}
