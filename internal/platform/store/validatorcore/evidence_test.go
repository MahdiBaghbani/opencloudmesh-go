// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"strings"
	"testing"
)

func capabilityFileOpenedFact(runID, reason, leg string) ApplyEvidenceFactInput {
	return ApplyEvidenceFactInput{
		TestRunID:    runID,
		Area:         evidenceAreaCapability,
		Step:         evidenceStepFileOpened,
		ReasonCode:   reason,
		Severity:     "info",
		AffectsGrade: false,
		Leg:          leg,
	}
}

func countEvidenceForRun(t *testing.T, core *Core, runID string) int64 {
	t.Helper()

	return countByTestRunID(t, core.DB(), &EvidenceRow{}, runID, "evidence_row")
}

func TestApplyEvidenceFact_AdvancesFromForwardShareSent(t *testing.T) {
	t.Parallel()

	reasons := []string{evidenceReasonTokenExchange, evidenceReasonWebDAVGet}

	for _, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			runID := "run-advance-" + reason

			seedActiveRunInState(t, core, runID, StateForwardShareSent)

			if err := core.ApplyEvidenceFact(ctx, capabilityFileOpenedFact(
				runID,
				reason,
				evidenceLegForward,
			)); err != nil {
				t.Fatalf("ApplyEvidenceFact: %v", err)
			}

			assertActiveInState(t, core, runID, StateCapabilityExercise)

			if got := countEvidenceForRun(t, core, runID); got != 1 {
				t.Fatalf("evidence rows = %d, want 1", got)
			}
		})
	}
}

func TestApplyEvidenceFact_LeavesOtherStatesUnchanged(t *testing.T) {
	t.Parallel()

	states := []string{
		StateActiveRunning,
		StateInviteMinted,
		StateInviteAccepted,
		StateReverseAwaitingInvite,
		StateReverseInviteAccepted,
		StateCapabilityExercise,
		StateReverseAwaitingShare,
	}

	for _, state := range states {
		t.Run(state, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			runID := "run-no-advance-" + state

			seedActiveRunInState(t, core, runID, state)

			before, err := core.GetTestRun(ctx, runID)
			if err != nil {
				t.Fatalf("GetTestRun before: %v", err)
			}

			err = core.ApplyEvidenceFact(ctx, capabilityFileOpenedFact(
				runID,
				evidenceReasonTokenExchange,
				evidenceLegForward,
			))
			if err != nil {
				t.Fatalf("ApplyEvidenceFact: %v", err)
			}

			assertActiveInState(t, core, runID, state)

			got, err := core.GetTestRun(ctx, runID)
			if err != nil {
				t.Fatalf("GetTestRun after: %v", err)
			}

			if got.UpdatedAt != before.UpdatedAt {
				t.Fatalf("updated_at = %d, want unchanged %d", got.UpdatedAt, before.UpdatedAt)
			}

			if n := countEvidenceForRun(t, core, runID); n != 1 {
				t.Fatalf("evidence rows = %d, want 1", n)
			}
		})
	}
}

func TestApplyEvidenceFact_IgnoresReverseInviteFileOpened(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-reverse-ignore"

	seedActiveRunInState(t, core, runID, StateForwardShareSent)

	before, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun before: %v", err)
	}

	err = core.ApplyEvidenceFact(ctx, capabilityFileOpenedFact(
		runID,
		evidenceReasonTokenExchange,
		evidenceLegReverse,
	))
	if err != nil {
		t.Fatalf("ApplyEvidenceFact reverse: %v", err)
	}

	assertActiveInState(t, core, runID, StateForwardShareSent)

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after reverse: %v", err)
	}

	if got.UpdatedAt != before.UpdatedAt {
		t.Fatalf("updated_at = %d, want unchanged %d", got.UpdatedAt, before.UpdatedAt)
	}

	if n := countEvidenceForRun(t, core, runID); n != 0 {
		t.Fatalf("evidence rows after reverse = %d, want 0", n)
	}

	err = core.ApplyEvidenceFact(ctx, capabilityFileOpenedFact(
		runID,
		evidenceReasonTokenExchange,
		evidenceLegForward,
	))
	if err != nil {
		t.Fatalf("ApplyEvidenceFact forward after reverse: %v", err)
	}

	assertActiveInState(t, core, runID, StateCapabilityExercise)

	if n := countEvidenceForRun(t, core, runID); n != 1 {
		t.Fatalf("evidence rows after forward = %d, want 1", n)
	}
}

func TestApplyEvidenceFact_IdenticalReplayKeepsOneRow(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-replay"

	seedActiveRunInState(t, core, runID, StateForwardShareSent)

	fact := capabilityFileOpenedFact(runID, evidenceReasonTokenExchange, evidenceLegForward)

	if err := core.ApplyEvidenceFact(ctx, fact); err != nil {
		t.Fatalf("first ApplyEvidenceFact: %v", err)
	}

	afterFirst, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after first: %v", err)
	}

	err = core.ApplyEvidenceFact(ctx, fact)
	if err != nil {
		t.Fatalf("replay ApplyEvidenceFact: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after replay: %v", err)
	}

	if got.State != StateCapabilityExercise {
		t.Fatalf("state = %q, want %q", got.State, StateCapabilityExercise)
	}

	if got.UpdatedAt != afterFirst.UpdatedAt {
		t.Fatalf("updated_at = %d, want first-win stamp %d", got.UpdatedAt, afterFirst.UpdatedAt)
	}

	if !got.IsActive {
		t.Fatal("is_active = 0, want 1")
	}

	if got.FinishedAt != nil {
		t.Fatalf("finished_at = %v, want nil", got.FinishedAt)
	}

	if got.TerminalReason != nil {
		t.Fatalf("terminal_reason = %v, want nil", got.TerminalReason)
	}

	if n := countEvidenceForRun(t, core, runID); n != 1 {
		t.Fatalf("evidence rows = %d, want 1", n)
	}
}

func TestApplyEvidenceFact_DuplicateReasonDoesNotRecas(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-insert-gate"

	const sentinelUpdatedAt int64 = 111

	seedActiveRunInState(t, core, runID, StateForwardShareSent)

	fact := capabilityFileOpenedFact(runID, evidenceReasonWebDAVGet, evidenceLegForward)

	if err := core.ApplyEvidenceFact(ctx, fact); err != nil {
		t.Fatalf("first ApplyEvidenceFact: %v", err)
	}

	assertActiveInState(t, core, runID, StateCapabilityExercise)

	if err := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		Updates(map[string]any{
			colState:     StateForwardShareSent,
			colUpdatedAt: sentinelUpdatedAt,
		}).Error; err != nil {
		t.Fatalf("restore forward_share_sent: %v", err)
	}

	if err := core.ApplyEvidenceFact(ctx, fact); err != nil {
		t.Fatalf("second ApplyEvidenceFact: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after second: %v", err)
	}

	if got.State != StateForwardShareSent {
		t.Fatalf("state = %q, want %q after gated hop", got.State, StateForwardShareSent)
	}

	if got.UpdatedAt != sentinelUpdatedAt {
		t.Fatalf("updated_at = %d, want sentinel %d (second hop must not CAS)", got.UpdatedAt, sentinelUpdatedAt)
	}

	if n := countEvidenceForRun(t, core, runID); n != 1 {
		t.Fatalf("evidence rows = %d, want 1", n)
	}
}

func TestApplyEvidenceFact_RejectsEmptyAndUnknownLeg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		leg     string
		wantErr string
	}{
		{
			name:    "empty",
			leg:     "",
			wantErr: "empty evidence leg",
		},
		{
			name:    "unknown",
			leg:     "sideways",
			wantErr: "unknown evidence leg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			runID := "run-bad-leg-" + tt.name

			seedActiveRunInState(t, core, runID, StateForwardShareSent)

			before, err := core.GetTestRun(ctx, runID)
			if err != nil {
				t.Fatalf("GetTestRun before: %v", err)
			}

			err = core.ApplyEvidenceFact(ctx, capabilityFileOpenedFact(
				runID,
				evidenceReasonTokenExchange,
				tt.leg,
			))
			if err == nil {
				t.Fatal("expected empty or unknown leg to be rejected")
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}

			assertActiveInState(t, core, runID, StateForwardShareSent)

			got, err := core.GetTestRun(ctx, runID)
			if err != nil {
				t.Fatalf("GetTestRun after reject: %v", err)
			}

			if got.UpdatedAt != before.UpdatedAt {
				t.Fatalf("updated_at = %d, want unchanged %d", got.UpdatedAt, before.UpdatedAt)
			}

			if n := countEvidenceForRun(t, core, runID); n != 0 {
				t.Fatalf("evidence rows after reject = %d, want 0", n)
			}

			err = core.ApplyEvidenceFact(ctx, capabilityFileOpenedFact(
				runID,
				evidenceReasonTokenExchange,
				evidenceLegForward,
			))
			if err != nil {
				t.Fatalf("ApplyEvidenceFact forward after reject: %v", err)
			}

			assertActiveInState(t, core, runID, StateCapabilityExercise)

			if n := countEvidenceForRun(t, core, runID); n != 1 {
				t.Fatalf("evidence rows after forward = %d, want 1", n)
			}
		})
	}
}

func TestApplyEvidenceFact_ConcurrentSameRunWritesOnce(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-evidence-concurrent-same-run"

	seedActiveRunInState(t, core, runID, StateForwardShareSent)

	// Same-run capability file-open token_exchange on the forward leg.
	// SQLite serializes writers: one transaction commits the first-wins
	// insert and the guarded CAS, and the others either no-op on the unique
	// key or fail fast with SQLITE_BUSY. Both outcomes are safe; what must
	// hold is exactly one evidence row and exactly one state advance.
	fact := capabilityFileOpenedFact(
		runID,
		evidenceReasonTokenExchange,
		evidenceLegForward,
	)

	const writers = 8

	start := make(chan struct{})
	errs := make(chan error, writers)

	for range writers {
		go func() {
			<-start

			errs <- core.ApplyEvidenceFact(ctx, fact)
		}()
	}

	close(start)

	succeeded := 0

	for range writers {
		err := <-errs
		if err == nil {
			succeeded++

			continue
		}

		if !strings.Contains(err.Error(), "SQLITE_BUSY") {
			t.Fatalf("concurrent ApplyEvidenceFact error = %v, want nil or SQLITE_BUSY serialization", err)
		}
	}

	if succeeded == 0 {
		t.Fatal("at least one concurrent ApplyEvidenceFact must succeed")
	}

	assertActiveInState(t, core, runID, StateCapabilityExercise)

	if n := countEvidenceForRun(t, core, runID); n != 1 {
		t.Fatalf("evidence rows = %d, want 1 after concurrent same-run facts", n)
	}
}

func sharingAcceptFact(runID, leg string) ApplyEvidenceFactInput {
	return ApplyEvidenceFactInput{
		TestRunID:    runID,
		Area:         SpecificationAreaSharing,
		Step:         evidenceStepInviteAccepted,
		ReasonCode:   evidenceReasonReverseAccepted,
		Severity:     GradePass,
		AffectsGrade: true,
		Leg:          leg,
	}
}

func TestApplyEvidenceFact_AcceptsPassiveLeg(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-passive-leg"

	seedActiveRunInState(t, core, runID, StateForwardShareSent)

	if err := core.ApplyEvidenceFact(ctx, sharingAcceptFact(runID, evidenceLegPassive)); err != nil {
		t.Fatalf("ApplyEvidenceFact passive: %v", err)
	}

	if n := countEvidenceForRun(t, core, runID); n != 1 {
		t.Fatalf("evidence rows = %d, want 1", n)
	}

	var row EvidenceRow
	if err := core.DB().WithContext(ctx).Where("test_run_id = ?", runID).First(&row).Error; err != nil {
		t.Fatalf("load evidence: %v", err)
	}

	if row.Leg == nil || *row.Leg != evidenceLegPassive {
		t.Fatalf("leg = %v, want %q", row.Leg, evidenceLegPassive)
	}
}

func TestApplyEvidenceFact_RejectsReverseInviteArea(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-old-area"

	seedActiveRunInState(t, core, runID, StateForwardShareSent)

	err := core.ApplyEvidenceFact(ctx, ApplyEvidenceFactInput{
		TestRunID:    runID,
		Area:         "reverse_invite",
		Step:         evidenceStepInviteAccepted,
		ReasonCode:   evidenceReasonReverseAccepted,
		Severity:     GradePass,
		AffectsGrade: true,
		Leg:          evidenceLegReverse,
	})
	if err == nil {
		t.Fatal("expected reverse_invite area to be rejected")
	}

	if !strings.Contains(err.Error(), "unknown evidence area") {
		t.Fatalf("error = %v, want unknown evidence area", err)
	}

	if n := countEvidenceForRun(t, core, runID); n != 0 {
		t.Fatalf("evidence rows after reject = %d, want 0", n)
	}
}

func TestApplyEvidenceFact_PerLegUnique(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-per-leg"

	seedActiveRunInState(t, core, runID, StateForwardShareSent)

	if err := core.ApplyEvidenceFact(ctx, sharingAcceptFact(runID, evidenceLegForward)); err != nil {
		t.Fatalf("forward fact: %v", err)
	}

	if err := core.ApplyEvidenceFact(ctx, sharingAcceptFact(runID, evidenceLegReverse)); err != nil {
		t.Fatalf("reverse fact: %v", err)
	}

	if n := countEvidenceForRun(t, core, runID); n != 2 {
		t.Fatalf("evidence rows = %d, want 2 distinct legs", n)
	}
}
