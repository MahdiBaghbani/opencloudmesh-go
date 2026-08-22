// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
)

func TestPersistActiveExchangeAndFact_Idempotent(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-active-exchange"
	createTestRun(t, core.DB(), runID)

	draft := IncomingTokenExchange(runID)
	fact := TokenExchangedFact(runID, nil)

	if err := core.PersistActiveExchangeAndFact(ctx, draft, fact); err != nil {
		t.Fatalf("first persist: %v", err)
	}

	if err := core.PersistActiveExchangeAndFact(ctx, draft, fact); err != nil {
		t.Fatalf("retry persist: %v", err)
	}

	if got := countReportExchanges(t, core, runID); got != 1 {
		t.Fatalf("exchanges = %d, want 1", got)
	}

	if got := countEvidenceForRun(t, core, runID); got != 1 {
		t.Fatalf("evidence = %d, want 1", got)
	}

	var row EvidenceRow
	if err := core.DB().WithContext(ctx).Where("test_run_id = ?", runID).First(&row).Error; err != nil {
		t.Fatalf("load evidence: %v", err)
	}

	if row.ExchangeID == nil || *row.ExchangeID == 0 {
		t.Fatal("evidence must carry the persisted exchange id")
	}

	if row.Area != SpecificationAreaToken || !row.AffectsGrade {
		t.Fatalf("token evidence = %+v", row)
	}
}

func TestPersistActiveExchange_RejectsUnknownEndpoint(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	createTestRun(t, core.DB(), "run-bad-endpoint")

	_, err := core.PersistActiveExchange(t.Context(), ActiveExchangeDraft{
		TestRunID:  "run-bad-endpoint",
		EndpointID: "tls",
		Method:     "GET",
		URL:        "/tls",
		Direction:  exchangeDirectionOut,
		RequestID:  "bad",
		Leg:        evidenceLegPassive,
	})
	if err == nil {
		t.Fatal("tls endpoint draft must be rejected")
	}
}

func TestReverseInviteAcceptedFact_SharingReverseLeg(t *testing.T) {
	t.Parallel()

	fact := ReverseInviteAcceptedFact("run-reverse-accept", nil)
	if fact.Area != SpecificationAreaSharing {
		t.Fatalf("area = %q, want sharing", fact.Area)
	}

	if fact.Step != evidenceStepInviteAccepted || fact.ReasonCode != evidenceReasonReverseAccepted {
		t.Fatalf("step/reason = %q/%q, want invite_accepted/reverse_invite_accepted", fact.Step, fact.ReasonCode)
	}

	if fact.Leg != evidenceLegReverse || !fact.AffectsGrade {
		t.Fatalf("leg/affects = %q/%v, want reverse/true", fact.Leg, fact.AffectsGrade)
	}
}

func TestWebDAVTranscriptFact_DoesNotGrade(t *testing.T) {
	t.Parallel()

	fact := WebDAVTranscriptFact("run-webdav", nil)
	if fact.AffectsGrade {
		t.Fatal("webdav transcript fact must not affect grade")
	}

	if fact.Area != SpecificationAreaCapability {
		t.Fatalf("area = %q, want capability", fact.Area)
	}
}
