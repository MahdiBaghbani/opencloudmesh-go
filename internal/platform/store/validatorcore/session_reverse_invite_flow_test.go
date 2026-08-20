// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"

	"gorm.io/gorm"
)

func requireState(t *testing.T, core *Core, runID, want string) {
	t.Helper()

	run, err := core.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != want {
		t.Fatalf("state = %q, want %q", run.State, want)
	}
}

// countReverseAcceptEvidenceRows counts the reverse-invite accept evidence
// tuple written by the winning accept CAS.
func countReverseAcceptEvidenceRows(t *testing.T, core *Core, runID string) int {
	t.Helper()

	var count int64
	if err := core.DB().WithContext(t.Context()).
		Model(&EvidenceRow{}).
		Where("test_run_id = ? AND area = ? AND step = ? AND reason_code = ?",
			runID, "reverse_invite", "invite_accepted", "reverse_invite_accepted").
		Count(&count).Error; err != nil {
		t.Fatalf("count evidence rows: %v", err)
	}

	return int(count)
}

func TestRecordOutgoingInviteAccepted_AdvancesAndPinsShareWith(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-accept-out"

	seedReverseInviteRun(t, core, runID, StateInviteMinted)

	if err := core.RecordOutgoingInviteAccepted(ctx, runID, "alice"); err != nil {
		t.Fatalf("record: %v", err)
	}

	run, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != StateInviteAccepted {
		t.Fatalf("state = %q, want %q", run.State, StateInviteAccepted)
	}

	if run.DesignatedShareWith == nil || *run.DesignatedShareWith != "alice" {
		t.Fatalf("designated_share_with = %v, want alice", run.DesignatedShareWith)
	}
}

func TestRecordOutgoingInviteAccepted_IdempotentFromLaterStates(t *testing.T) {
	t.Parallel()

	for _, state := range statesAtOrPastInviteAccepted {
		t.Run(state, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			runID := "run-accept-idem"

			seedReverseInviteRun(t, core, runID, state)

			if err := core.RecordOutgoingInviteAccepted(ctx, runID, "alice"); err != nil {
				t.Fatalf("record from %q: %v", state, err)
			}

			requireState(t, core, runID, state)
		})
	}
}

func TestRecordOutgoingInviteAccepted_MissFromActiveRunning(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-accept-early"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	err := core.RecordOutgoingInviteAccepted(ctx, runID, "alice")
	if !errors.Is(err, ErrStateTransitionMiss) {
		t.Fatalf("record = %v, want ErrStateTransitionMiss", err)
	}

	requireState(t, core, runID, StateActiveRunning)
}

func TestSolicitReverse_TwoCASesAdvanceToAwaiting(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-solicit-basic"

	seedReverseInviteRun(t, core, runID, StateInviteAccepted)

	if err := core.SolicitReverse(ctx, runID); err != nil {
		t.Fatalf("solicit: %v", err)
	}

	requireState(t, core, runID, StateReverseAwaitingInvite)

	if err := core.SolicitReverse(ctx, runID); err != nil {
		t.Fatalf("solicit retry: %v", err)
	}

	requireState(t, core, runID, StateReverseAwaitingInvite)
}

func TestSolicitReverse_HealsSolicitedCrashNotch(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-solicit-notch"

	// Crash notch: the first CAS committed but the second never ran.
	seedReverseInviteRun(t, core, runID, StateReverseInviteSolicited)

	if err := core.SolicitReverse(ctx, runID); err != nil {
		t.Fatalf("solicit heal: %v", err)
	}

	requireState(t, core, runID, StateReverseAwaitingInvite)
}

func TestSolicitReverse_MissFromWrongState(t *testing.T) {
	t.Parallel()

	for _, state := range []string{StateActiveRunning, StateInviteMinted} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			runID := "run-solicit-wrong"

			seedReverseInviteRun(t, core, runID, state)

			err := core.SolicitReverse(ctx, runID)
			if !errors.Is(err, ErrStateTransitionMiss) {
				t.Fatalf("solicit from %q = %v, want ErrStateTransitionMiss", state, err)
			}

			requireState(t, core, runID, state)
		})
	}
}

func TestImportReverseInvite_BindsSlotAndAdvances(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-import-basic"

	seedReverseInviteRun(t, core, runID, StateReverseAwaitingInvite)

	if err := core.ImportReverseInvite(ctx, runID, "token-1", "incoming-1"); err != nil {
		t.Fatalf("import: %v", err)
	}

	run, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != StateReverseInviteImported {
		t.Fatalf("state = %q, want %q", run.State, StateReverseInviteImported)
	}

	if run.ReverseInviteToken == nil || *run.ReverseInviteToken != "token-1" {
		t.Fatalf("reverse_invite_token = %v, want token-1", run.ReverseInviteToken)
	}

	if run.ReverseInviteImportedAt == nil {
		t.Fatal("reverse_invite_imported_at is nil, want set")
	}

	corr, err := core.GetShareCorrelation(ctx, runID, RoleIncomingInvite, LocalIdentityB)
	if err != nil {
		t.Fatalf("GetShareCorrelation: %v", err)
	}

	if corr.InviteID == nil || *corr.InviteID != "incoming-1" {
		t.Fatalf("invite id = %v, want incoming-1", corr.InviteID)
	}

	if corr.ProviderID != "token-1" {
		t.Fatalf("provider id = %q, want token-1", corr.ProviderID)
	}

	if corr.SenderHost != "peer.example" {
		t.Fatalf("sender host = %q, want peer.example", corr.SenderHost)
	}
}

func TestImportReverseInvite_IdempotentSameToken(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-import-idem"

	seedReverseInviteRun(t, core, runID, StateReverseAwaitingInvite)

	for range 3 {
		if err := core.ImportReverseInvite(ctx, runID, "token-1", "incoming-1"); err != nil {
			t.Fatalf("import retry: %v", err)
		}
	}

	if got := countCorrelations(t, core, runID, RoleIncomingInvite); got != 1 {
		t.Fatalf("correlation rows = %d, want 1", got)
	}

	requireState(t, core, runID, StateReverseInviteImported)
}

func TestImportReverseInvite_FirstTokenWins(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-import-conflict"

	seedReverseInviteRun(t, core, runID, StateReverseAwaitingInvite)

	if err := core.ImportReverseInvite(ctx, runID, "token-1", "incoming-1"); err != nil {
		t.Fatalf("import: %v", err)
	}

	err := core.ImportReverseInvite(ctx, runID, "token-other", "incoming-2")
	if !errors.Is(err, ErrShareCorrelationConflict) {
		t.Fatalf("import different token = %v, want ErrShareCorrelationConflict", err)
	}

	run, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != StateReverseInviteImported {
		t.Fatalf("state = %q, want %q (no advance)", run.State, StateReverseInviteImported)
	}

	if run.ReverseInviteToken == nil || *run.ReverseInviteToken != "token-1" {
		t.Fatalf("reverse_invite_token = %v, want token-1 (first wins)", run.ReverseInviteToken)
	}

	if got := countCorrelations(t, core, runID, RoleIncomingInvite); got != 1 {
		t.Fatalf("correlation rows = %d, want 1", got)
	}
}

func TestImportReverseInvite_MissOutsideAwaiting(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-import-wrong-state"

	seedReverseInviteRun(t, core, runID, StateInviteAccepted)

	err := core.ImportReverseInvite(ctx, runID, "token-1", "incoming-1")
	if !errors.Is(err, ErrStateTransitionMiss) {
		t.Fatalf("import = %v, want ErrStateTransitionMiss", err)
	}

	if got := countCorrelations(t, core, runID, RoleIncomingInvite); got != 0 {
		t.Fatalf("correlation rows = %d, want 0 (rolled back)", got)
	}

	requireState(t, core, runID, StateInviteAccepted)
}

func TestAcceptReverseInvite_AdvancesAndWritesEvidenceOnce(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-accept-rev"

	seedReverseInviteRun(t, core, runID, StateReverseAwaitingInvite)

	if err := core.ImportReverseInvite(ctx, runID, "token-1", "incoming-1"); err != nil {
		t.Fatalf("import: %v", err)
	}

	if err := core.AcceptReverseInvite(ctx, runID); err != nil {
		t.Fatalf("accept: %v", err)
	}

	requireState(t, core, runID, StateReverseInviteAccepted)

	if got := countReverseAcceptEvidenceRows(t, core, runID); got != 1 {
		t.Fatalf("evidence rows = %d, want 1", got)
	}

	var row EvidenceRow
	if err := core.DB().WithContext(ctx).
		Where("test_run_id = ? AND area = ?", runID, "reverse_invite").
		First(&row).Error; err != nil {
		t.Fatalf("load evidence row: %v", err)
	}

	if !row.AffectsGrade {
		t.Fatal("affects_grade = false, want true")
	}

	if row.Severity != GradePass {
		t.Fatalf("severity = %q, want %q", row.Severity, GradePass)
	}

	// Retry: idempotent success, and the evidence tuple is not written twice.
	if err := core.AcceptReverseInvite(ctx, runID); err != nil {
		t.Fatalf("accept retry: %v", err)
	}

	if got := countReverseAcceptEvidenceRows(t, core, runID); got != 1 {
		t.Fatalf("evidence rows after retry = %d, want 1", got)
	}
}

func TestAcceptReverseInvite_IdempotentFromLaterStates(t *testing.T) {
	t.Parallel()

	for _, state := range statesAtOrPastReverseInviteAccepted {
		t.Run(state, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			runID := "run-accept-later"

			seedReverseInviteRun(t, core, runID, state)

			// A run already at or past reverse_invite_accepted is not
			// re-accepted and never regressed; the accept is a no-op.
			if err := core.AcceptReverseInvite(ctx, runID); err != nil {
				t.Fatalf("accept from %q: %v", state, err)
			}

			requireState(t, core, runID, state)

			if got := countReverseAcceptEvidenceRows(t, core, runID); got != 0 {
				t.Fatalf("evidence rows from %q = %d, want 0 (no re-accept)", state, got)
			}
		})
	}
}

func TestAcceptReverseInvite_EvidenceFailureRollsBackCAS(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-accept-evidence-rollback"

	seedReverseInviteRun(t, core, runID, StateReverseAwaitingInvite)

	if err := core.ImportReverseInvite(ctx, runID, "token-1", "incoming-1"); err != nil {
		t.Fatalf("import: %v", err)
	}

	// Force the evidence insert inside the accept transaction to fail; the
	// whole transaction, including the state CAS, must roll back.
	const cbName = "test_fail_reverse_accept_evidence"

	injected := errors.New("injected evidence failure")

	if err := core.DB().Callback().Create().Before("gorm:create").Register(cbName, func(db *gorm.DB) {
		row, ok := db.Statement.Model.(*EvidenceRow)
		if !ok || row.TestRunID != runID {
			return
		}

		// AddError returns the statement's aggregated error, which must be
		// the error just added; anything else means the injection misfired.
		if addErr := db.AddError(injected); !errors.Is(addErr, injected) {
			t.Errorf("inject evidence failure: got %v", addErr)
		}
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}

	defer func() {
		if err := core.DB().Callback().Create().Remove(cbName); err != nil {
			t.Errorf("remove callback: %v", err)
		}
	}()

	err := core.AcceptReverseInvite(ctx, runID)
	if !errors.Is(err, injected) {
		t.Fatalf("accept = %v, want injected evidence failure", err)
	}

	requireState(t, core, runID, StateReverseInviteImported)

	if got := countReverseAcceptEvidenceRows(t, core, runID); got != 0 {
		t.Fatalf("evidence rows after rollback = %d, want 0", got)
	}
}

func TestAcceptReverseInvite_MissFromWrongState(t *testing.T) {
	t.Parallel()

	for _, state := range []string{StateReverseAwaitingInvite, StateInviteAccepted, StateActiveRunning, StateTerminalFail, StateInterrupted} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			runID := "run-accept-wrong"

			seedReverseInviteRun(t, core, runID, state)

			err := core.AcceptReverseInvite(ctx, runID)
			if !errors.Is(err, ErrStateTransitionMiss) {
				t.Fatalf("accept from %q = %v, want ErrStateTransitionMiss", state, err)
			}

			requireState(t, core, runID, state)

			if got := countReverseAcceptEvidenceRows(t, core, runID); got != 0 {
				t.Fatalf("evidence rows from %q = %d, want 0", state, got)
			}
		})
	}
}
