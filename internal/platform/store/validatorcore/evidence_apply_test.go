// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"strings"
	"testing"
)

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

func TestApplyEvidenceFact_KeepsFirstSeverity(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-first-wins-severity"

	seedActiveRunInState(t, core, runID, StateForwardShareSent)

	fail := jwksProbeFact(runID, GradeFail)
	pass := jwksProbeFact(runID, GradePass)

	if err := core.ApplyEvidenceFact(ctx, fail); err != nil {
		t.Fatalf("first ApplyEvidenceFact: %v", err)
	}

	if err := core.ApplyEvidenceFact(ctx, pass); err != nil {
		t.Fatalf("second ApplyEvidenceFact: %v", err)
	}

	got := mustLoadEvidence(t, core, runID)
	if got.Severity != GradeFail {
		t.Fatalf("severity = %q, want first-wins %q", got.Severity, GradeFail)
	}

	if n := countEvidenceForRun(t, core, runID); n != 1 {
		t.Fatalf("evidence rows = %d, want 1", n)
	}
}

func TestReplaceEvidenceFact_LastWinsSeverity(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-last-wins-severity"

	seedActiveRunInState(t, core, runID, StateForwardShareSent)

	if err := core.ApplyEvidenceFact(ctx, jwksProbeFact(runID, GradeFail)); err != nil {
		t.Fatalf("ApplyEvidenceFact fail: %v", err)
	}

	pass := jwksProbeFact(runID, GradePass)
	pass.PayloadRedacted = `{"grade":"pass"}`
	pass.ReasonCode = "jwks_ok"

	if err := core.ReplaceEvidenceFact(ctx, pass); err != nil {
		t.Fatalf("ReplaceEvidenceFact: %v", err)
	}

	got := mustLoadEvidence(t, core, runID)
	if got.Severity != GradePass {
		t.Fatalf("severity = %q, want last-wins %q", got.Severity, GradePass)
	}

	if got.ReasonCode != "jwks_ok" {
		t.Fatalf("reason_code = %q, want last-wins jwks_ok", got.ReasonCode)
	}

	if got.PayloadRedacted == nil || *got.PayloadRedacted != `{"grade":"pass"}` {
		t.Fatalf("payload = %v, want last-wins pass payload", got.PayloadRedacted)
	}

	if n := countEvidenceForRun(t, core, runID); n != 1 {
		t.Fatalf("evidence rows = %d, want 1 after last-wins replace", n)
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
