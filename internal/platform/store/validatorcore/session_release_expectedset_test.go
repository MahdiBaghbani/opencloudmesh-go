// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

// observeStateOnConn reads the current state on its own connection the way a
// stall writer observes the pre-image before issuing its UPDATE.
func observeStateOnConn(t *testing.T, conn *sql.Conn, runID string) string {
	t.Helper()

	tx, err := conn.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin stale read: %v", err)
	}

	var observed string

	scanErr := tx.QueryRowContext(
		t.Context(),
		"SELECT state FROM test_run WHERE test_run_id = ?",
		runID,
	).Scan(&observed)
	if scanErr != nil {
		t.Fatalf("stale read: %v", scanErr)
	}

	if rollbackErr := tx.Rollback(); rollbackErr != nil {
		t.Fatalf("rollback stale read: %v", rollbackErr)
	}

	return observed
}

// runGuardedCASOnConn performs the concurrent guarded forward transition that
// races a stall terminal write.
func runGuardedCASOnConn(t *testing.T, conn *sql.Conn, runID, fromState, toState string) {
	t.Helper()

	res, err := conn.ExecContext(t.Context(),
		"UPDATE test_run SET state = ?, updated_at = ? WHERE test_run_id = ? AND is_active = 1 AND state = ?",
		toState,
		time.Now().Unix(),
		runID,
		fromState,
	)
	if err != nil {
		t.Fatalf("concurrent CAS: %v", err)
	}

	moved, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("CAS rows affected: %v", err)
	}

	if moved != 1 {
		t.Fatalf("concurrent CAS affected %d rows, want 1", moved)
	}
}

func assertActiveInState(t *testing.T, core *Core, runID, state string) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive {
		t.Fatal("is_active = 0, want 1")
	}

	if got.State != state {
		t.Fatalf("state = %q, want %q", got.State, state)
	}

	if got.FinishedAt != nil {
		t.Fatalf("finished_at = %v, want nil", got.FinishedAt)
	}

	if got.TerminalReason != nil {
		t.Fatalf("terminal_reason = %v, want nil", got.TerminalReason)
	}
}

func assertReleasedToPass(t *testing.T, core *Core, runID string) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive || got.State != StateTerminalPass {
		t.Fatalf("is_active=%v state=%q, want released terminal_pass", got.IsActive, got.State)
	}
}

func TestReleaseActiveTerminalFrom_PassExpectedSet(t *testing.T) {
	t.Parallel()

	t.Run("capability exercise releases to pass", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		runID := "run-pass-cap"

		seedActiveRunInState(t, core, runID, StateCapabilityExercise)

		if err := core.ReleaseActiveTerminalFrom(t.Context(), runID, ActivePassExpectedStates(), terminalPassUpdate()); err != nil {
			t.Fatalf("ReleaseActiveTerminalFrom: %v", err)
		}

		assertReleasedToPass(t, core, runID)
	})

	t.Run("reverse awaiting share releases to pass", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		runID := "run-pass-reverse"

		seedActiveRunInState(t, core, runID, StateReverseAwaitingShare)

		if err := core.ReleaseActiveTerminalFrom(t.Context(), runID, ActivePassExpectedStates(), terminalPassUpdate()); err != nil {
			t.Fatalf("ReleaseActiveTerminalFrom: %v", err)
		}

		assertReleasedToPass(t, core, runID)
	})

	t.Run("other active states miss the pass set", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		runID := "run-pass-miss"

		seedActiveRunInState(t, core, runID, StateForwardShareSent)

		err := core.ReleaseActiveTerminalFrom(t.Context(), runID, ActivePassExpectedStates(), terminalPassUpdate())
		if !errors.Is(err, ErrStateTransitionMiss) {
			t.Fatalf("error = %v, want ErrStateTransitionMiss", err)
		}

		assertActiveInState(t, core, runID, StateForwardShareSent)
	})
}

func TestReleaseActiveTerminalFrom_AcceptsFullActiveNonTerminalSet(t *testing.T) {
	t.Parallel()

	allActiveNonTerminal := []string{
		StateActiveRunning,
		StateInviteMinted,
		StateInviteAccepted,
		StateReverseAwaitingInvite,
		StateReverseInviteAccepted,
		StateForwardShareSent,
		StateCapabilityExercise,
		StateReverseAwaitingShare,
	}

	for _, state := range allActiveNonTerminal {
		t.Run(state, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			runID := "run-release-any-" + state

			seedActiveRunInState(t, core, runID, state)

			if err := core.ReleaseActiveTerminalFrom(t.Context(), runID, allActiveNonTerminal, ActiveTerminalUpdate{
				State:          StateInterrupted,
				TerminalReason: "startup_unrecoverable_active",
			}); err != nil {
				t.Fatalf("ReleaseActiveTerminalFrom from %s: %v", state, err)
			}

			got, err := core.GetTestRun(t.Context(), runID)
			if err != nil {
				t.Fatalf("GetTestRun: %v", err)
			}

			if got.IsActive || got.State != StateInterrupted {
				t.Fatalf("is_active=%v state=%q, want interrupted inactive", got.IsActive, got.State)
			}
		})
	}
}

func TestReleaseActiveTerminalFrom_StaleExpectedSetMissesAfterConcurrentCAS(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-release-race"

	seedActiveRunInState(t, core, runID, StateCapabilityExercise)

	conn1, conn2 := acquireTwoSQLConns(t, core)

	observed := observeStateOnConn(t, conn1, runID)
	if observed != StateCapabilityExercise {
		t.Fatalf("observed state = %q, want %q", observed, StateCapabilityExercise)
	}

	// A concurrent guarded CAS moves the session forward before the stall
	// writer's UPDATE reaches the database.
	runGuardedCASOnConn(t, conn2, runID, StateCapabilityExercise, StateReverseAwaitingShare)

	// The stall write carries its stale singleton expected set and must miss
	// instead of rewriting the row the CAS already advanced.
	stallErr := core.ReleaseActiveTerminalFrom(ctx, runID, []string{StateCapabilityExercise}, ActiveTerminalUpdate{
		State:          StateTerminalFail,
		TerminalReason: ReasonOperatorAborted,
	})
	if !errors.Is(stallErr, ErrStateTransitionMiss) {
		t.Fatalf("stall release error = %v, want ErrStateTransitionMiss", stallErr)
	}

	assertActiveInState(t, core, runID, StateReverseAwaitingShare)

	// The pair expected set still releases from the CAS post-state.
	if err := core.ReleaseActiveTerminalFrom(ctx, runID, ActivePassExpectedStates(), terminalPassUpdate()); err != nil {
		t.Fatalf("release from CAS post-state: %v", err)
	}

	assertReleasedToPass(t, core, runID)
}

func TestReleaseActiveTerminalExcept_ValidatesExclusionAndTarget(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-except-validation"

	seedActiveRunInState(t, core, runID, StateActiveRunning)

	update := ActiveTerminalUpdate{State: StateTerminalFail, TerminalReason: ReasonActiveHardFail}

	// The terminal states are always excluded by construction, so naming one
	// as an extra exclusion is a caller error, not a no-op.
	if err := core.ReleaseActiveTerminalExcept(ctx, runID, []string{StateTerminalPass}, update); !errors.Is(err, ErrTerminalExclusionTerminal) {
		t.Fatalf("terminal extra exclusion error = %v, want ErrTerminalExclusionTerminal", err)
	}

	if err := core.ReleaseActiveTerminalExcept(ctx, runID, nil, ActiveTerminalUpdate{
		State:          StateActiveRunning,
		TerminalReason: ReasonActiveHardFail,
	}); !errors.Is(err, ErrTerminalStateInvalid) {
		t.Fatalf("non-terminal target error = %v, want ErrTerminalStateInvalid", err)
	}

	assertActiveInState(t, core, runID, StateActiveRunning)
}
