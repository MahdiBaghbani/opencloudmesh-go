// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
)

func TestLoadSpecificationRating_ScopesAndOrdersInputs(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	createTestRun(t, core.DB(), "run-a")
	createTestRun(t, core.DB(), "run-b")

	passive := evidenceLegPassive
	late := &EvidenceRow{
		TestRunID:    "run-a",
		Leg:          &passive,
		Area:         SpecificationAreaDiscovery,
		Step:         "late",
		ReasonCode:   "late",
		Severity:     GradePass,
		AffectsGrade: true,
		CreatedAt:    20,
	}
	early := &EvidenceRow{
		TestRunID:    "run-a",
		Leg:          &passive,
		Area:         SpecificationAreaJWKS,
		Step:         "early",
		ReasonCode:   "early",
		Severity:     GradeWarn,
		AffectsGrade: true,
		CreatedAt:    10,
	}
	other := &EvidenceRow{
		TestRunID:    "run-b",
		Leg:          &passive,
		Area:         SpecificationAreaTLS,
		Step:         "other",
		ReasonCode:   "other",
		Severity:     GradeFail,
		AffectsGrade: true,
		CreatedAt:    1,
	}

	for _, row := range []*EvidenceRow{late, early, other} {
		if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
			t.Fatalf("seed evidence: %v", err)
		}
	}

	foreignExchange := &ReportExchange{
		TestRunID:  "run-a",
		Seq:        1,
		CapturedAt: 1,
		Direction:  "out",
		EndpointID: "discovery",
		Method:     "GET",
		URL:        "https://peer.example/ocm",
		CreatedAt:  1,
	}

	if err := core.DB().WithContext(ctx).Create(foreignExchange).Error; err != nil {
		t.Fatalf("seed exchange: %v", err)
	}

	runA, err := core.GetTestRun(ctx, "run-a")
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	runA.State = StateTerminalPass

	score, evidence, err := core.LoadSpecificationRating(ctx, runA)
	if err != nil {
		t.Fatalf("LoadSpecificationRating: %v", err)
	}

	if len(evidence) != 2 {
		t.Fatalf("evidence = %d, want 2 evidence rows", len(evidence))
	}

	if evidence[0].Area != SpecificationAreaJWKS || evidence[1].Area != SpecificationAreaDiscovery {
		t.Fatalf("row order = %q then %q", evidence[0].Area, evidence[1].Area)
	}

	for _, item := range evidence {
		if item.Area == SpecificationAreaTLS {
			t.Fatal("loaded rows from another run")
		}

		if item.Source != specificationEvidenceSourceRow {
			t.Fatalf("source = %q, want evidence row", item.Source)
		}

		if item.Leg != evidenceLegPassive {
			t.Fatalf("leg = %q, want %q from evidence_row", item.Leg, evidenceLegPassive)
		}
	}

	assertGradeEq(t, areaByName(score, SpecificationAreaJWKS).Grade, GradeWarn)
	assertGradeEq(t, areaByName(score, SpecificationAreaDiscovery).Grade, GradePass)
	assertNilGrade(t, areaByName(score, SpecificationAreaTLS).Grade)
}

func TestHasReverseInviteAcceptance_RequiresReverseLeg(t *testing.T) {
	t.Parallel()

	tuple := func(leg string) EvidenceRow {
		row := EvidenceRow{
			Area:       SpecificationAreaSharing,
			Step:       evidenceStepInviteAccepted,
			ReasonCode: evidenceReasonReverseAccepted,
		}
		if leg != "" {
			row.Leg = &leg
		}

		return row
	}

	if hasReverseInviteAcceptance([]EvidenceRow{tuple("")}) {
		t.Fatal("nil leg must not count as reverse acceptance")
	}

	if hasReverseInviteAcceptance([]EvidenceRow{tuple(evidenceLegPassive)}) {
		t.Fatal("passive leg must not count as reverse acceptance")
	}

	if hasReverseInviteAcceptance([]EvidenceRow{tuple(evidenceLegForward)}) {
		t.Fatal("forward leg must not count as reverse acceptance")
	}

	if !hasReverseInviteAcceptance([]EvidenceRow{tuple(evidenceLegReverse)}) {
		t.Fatal("reverse leg must count as reverse acceptance")
	}
}

func TestRateSpecification_NonReverseLegDoesNotGradeReverseAcceptance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		leg     string
		wantLeg string
	}{
		{name: "passive", leg: evidenceLegPassive, wantLeg: evidenceLegPassive},
		{name: "forward", leg: evidenceLegForward, wantLeg: evidenceLegForward},
		{name: "empty", leg: "", wantLeg: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			row := EvidenceRow{
				Area:         SpecificationAreaSharing,
				Step:         evidenceStepInviteAccepted,
				ReasonCode:   evidenceReasonReverseAccepted,
				Severity:     GradePass,
				AffectsGrade: true,
			}
			if tt.leg != "" {
				row.Leg = &tt.leg
			}

			score, evidence, err := RateSpecification(terminalPassRun(), []EvidenceRow{row}, nil)
			if err != nil {
				t.Fatalf("RateSpecification: %v", err)
			}

			assertNilGrade(t, areaByName(score, SpecificationAreaSharing).Grade)
			assertNilGrade(t, score.Grade)

			if len(evidence) != 1 {
				t.Fatalf("evidence = %d, want 1 (row is listed, not scored)", len(evidence))
			}

			if evidence[0].Leg != tt.wantLeg {
				t.Fatalf("leg = %q, want %q", evidence[0].Leg, tt.wantLeg)
			}
		})
	}
}
