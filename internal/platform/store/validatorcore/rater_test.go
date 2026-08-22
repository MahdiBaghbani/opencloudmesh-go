// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"strings"
	"testing"
)

func affectingRow(area, severity string) EvidenceRow {
	return EvidenceRow{
		Area:         area,
		Step:         "observe",
		ReasonCode:   severity + "-reason",
		Severity:     severity,
		AffectsGrade: true,
	}
}

func terminalPassRun() *TestRun {
	fail := GradeFail

	return &TestRun{
		TestRunID:    "run-rate",
		State:        StateTerminalPass,
		OverallGrade: &fail,
	}
}

func areaByName(score SpecificationScore, name string) SpecificationAreaScore {
	for _, area := range score.Areas {
		if area.Area == name {
			return area
		}
	}

	return SpecificationAreaScore{}
}

func assertGradeEq(t *testing.T, got *string, want string) {
	t.Helper()

	if got == nil || *got != want {
		t.Fatalf("grade = %v, want %s", got, want)
	}
}

func assertNilGrade(t *testing.T, got *string) {
	t.Helper()

	if got != nil {
		t.Fatalf("grade = %q, want nil", *got)
	}
}

func assertCoverage(t *testing.T, score SpecificationScore, assessed int) {
	t.Helper()

	if score.TotalAreas != len(specificationAreaOrder) {
		t.Fatalf("totalAreas = %d, want %d", score.TotalAreas, len(specificationAreaOrder))
	}

	if score.AssessedAreas != assessed {
		t.Fatalf("assessedAreas = %d, want %d", score.AssessedAreas, assessed)
	}

	if len(score.Areas) != len(statsAreaOrder) {
		t.Fatalf("areas len = %d, want %d", len(score.Areas), len(statsAreaOrder))
	}

	for i, spec := range statsAreaOrder {
		if score.Areas[i].Area != spec.Name {
			t.Fatalf("areas[%d] = %q, want %q", i, score.Areas[i].Area, spec.Name)
		}
	}
}

func TestRateSpecification_AllPassTerminal(t *testing.T) {
	t.Parallel()

	rows := make([]EvidenceRow, 0, len(specificationAreaOrder))
	for _, area := range specificationAreaOrder {
		rows = append(rows, affectingRow(area, GradePass))
	}

	score, evidence, err := RateSpecification(terminalPassRun(), rows, nil)
	if err != nil {
		t.Fatalf("RateSpecification: %v", err)
	}

	assertGradeEq(t, score.Grade, GradePass)
	assertCoverage(t, score, 8)

	if !score.Terminal || score.State != StateTerminalPass {
		t.Fatalf("state = %q terminal=%v", score.State, score.Terminal)
	}

	if len(evidence) != 8 {
		t.Fatalf("evidence = %d, want 8", len(evidence))
	}

	for _, area := range score.Areas {
		assertGradeEq(t, area.Grade, GradePass)

		if area.EvidenceCount != 1 || area.GradedEvidenceCount != 1 {
			t.Fatalf("%s counts = %d/%d", area.Area, area.EvidenceCount, area.GradedEvidenceCount)
		}
	}
}

func TestRateSpecification_WarnOnly(t *testing.T) {
	t.Parallel()

	rows := []EvidenceRow{
		affectingRow(SpecificationAreaDiscovery, GradePass),
		affectingRow(SpecificationAreaTLS, "warning"),
	}

	score, _, err := RateSpecification(terminalPassRun(), rows, nil)
	if err != nil {
		t.Fatalf("RateSpecification: %v", err)
	}

	assertGradeEq(t, score.Grade, GradeWarn)
	assertGradeEq(t, areaByName(score, SpecificationAreaTLS).Grade, GradeWarn)
	assertGradeEq(t, areaByName(score, SpecificationAreaDiscovery).Grade, GradePass)
}

func TestRateSpecification_FailDominates(t *testing.T) {
	t.Parallel()

	rows := []EvidenceRow{
		affectingRow(SpecificationAreaJWKS, GradePass),
		{
			Area:         SpecificationAreaJWKS,
			Step:         "warn",
			ReasonCode:   "jwks-warn",
			Severity:     "important",
			AffectsGrade: true,
		},
		{
			Area:         SpecificationAreaJWKS,
			Step:         "fail",
			ReasonCode:   "jwks-fail",
			Severity:     "critical",
			AffectsGrade: true,
		},
	}

	score, _, err := RateSpecification(terminalPassRun(), rows, nil)
	if err != nil {
		t.Fatalf("RateSpecification: %v", err)
	}

	assertGradeEq(t, areaByName(score, SpecificationAreaJWKS).Grade, GradeFail)
	assertGradeEq(t, score.Grade, GradeFail)
}

func TestRateSpecification_TerminalFailWithoutEvidence(t *testing.T) {
	t.Parallel()

	run := &TestRun{TestRunID: "run-fail", State: StateTerminalFail}

	score, evidence, err := RateSpecification(run, nil, nil)
	if err != nil {
		t.Fatalf("RateSpecification: %v", err)
	}

	assertGradeEq(t, score.Grade, GradeFail)
	assertCoverage(t, score, 0)

	if evidence == nil || len(evidence) != 0 {
		t.Fatalf("evidence = %#v, want empty slice", evidence)
	}
}

func TestRateSpecification_NoEvidenceIsUnassessed(t *testing.T) {
	t.Parallel()

	score, evidence, err := RateSpecification(terminalPassRun(), nil, nil)
	if err != nil {
		t.Fatalf("RateSpecification: %v", err)
	}

	assertNilGrade(t, score.Grade)
	assertCoverage(t, score, 0)

	if evidence == nil || len(evidence) != 0 {
		t.Fatalf("evidence = %#v, want empty slice", evidence)
	}
}

func TestRateSpecification_InformationalEvidenceDoesNotGrade(t *testing.T) {
	t.Parallel()

	rows := []EvidenceRow{{
		Area:         SpecificationAreaDiscovery,
		Step:         "note",
		ReasonCode:   "fatal-note",
		Severity:     "fatal",
		AffectsGrade: false,
	}}

	score, evidence, err := RateSpecification(terminalPassRun(), rows, nil)
	if err != nil {
		t.Fatalf("RateSpecification: %v", err)
	}

	assertNilGrade(t, score.Grade)
	assertNilGrade(t, areaByName(score, SpecificationAreaDiscovery).Grade)

	if len(evidence) != 1 || evidence[0].Severity != "fatal" || evidence[0].AffectsGrade {
		t.Fatalf("evidence = %#v", evidence)
	}

	if areaByName(score, SpecificationAreaDiscovery).EvidenceCount != 1 {
		t.Fatal("informational row must count as evidence")
	}

	if areaByName(score, SpecificationAreaDiscovery).GradedEvidenceCount != 0 {
		t.Fatal("informational row must not count as graded evidence")
	}
}

func TestRateSpecification_NonTerminalHasNoOverallGrade(t *testing.T) {
	t.Parallel()

	run := &TestRun{TestRunID: "run-live", State: StateActiveRunning}

	score, _, err := RateSpecification(run, []EvidenceRow{
		affectingRow(SpecificationAreaSharing, GradeFail),
	}, nil)
	if err != nil {
		t.Fatalf("RateSpecification: %v", err)
	}

	assertNilGrade(t, score.Grade)
	assertGradeEq(t, areaByName(score, SpecificationAreaSharing).Grade, GradeFail)

	if score.Terminal {
		t.Fatal("non-terminal run must not be marked terminal")
	}
}

func TestRateSpecification_InterruptedHasNoOverallGrade(t *testing.T) {
	t.Parallel()

	run := &TestRun{TestRunID: "run-int", State: StateInterrupted}

	score, _, err := RateSpecification(run, []EvidenceRow{
		affectingRow(SpecificationAreaToken, GradePass),
		affectingRow(SpecificationAreaCapability, GradeWarn),
	}, nil)
	if err != nil {
		t.Fatalf("RateSpecification: %v", err)
	}

	assertNilGrade(t, score.Grade)
	assertGradeEq(t, areaByName(score, SpecificationAreaToken).Grade, GradePass)
	assertGradeEq(t, areaByName(score, SpecificationAreaCapability).Grade, GradeWarn)

	if !score.Terminal {
		t.Fatal("interrupted must be terminal")
	}
}

func TestRateSpecification_PassiveOnlyIsAtMostFour(t *testing.T) {
	t.Parallel()

	rows := []EvidenceRow{
		affectingRow(SpecificationAreaDiscovery, GradePass),
		affectingRow(SpecificationAreaTLS, GradePass),
		affectingRow(SpecificationAreaJWKS, GradePass),
		affectingRow(SpecificationAreaHTTPSig, GradePass),
	}

	score, _, err := RateSpecification(terminalPassRun(), rows, []ReportExchange{{
		EndpointID: EndpointShares,
		Method:     "POST",
	}})
	if err != nil {
		t.Fatalf("RateSpecification: %v", err)
	}

	assertCoverage(t, score, 4)
	assertGradeEq(t, score.Grade, GradePass)

	if areaByName(score, SpecificationAreaSharing).Grade != nil ||
		areaByName(score, SpecificationAreaNotification).Grade != nil ||
		areaByName(score, SpecificationAreaToken).Grade != nil ||
		areaByName(score, SpecificationAreaCapability).Grade != nil {
		t.Fatal("passive-only fixture must leave active areas unassessed")
	}
}

func TestRateSpecification_ActiveFullReachesEight(t *testing.T) {
	t.Parallel()

	rows := make([]EvidenceRow, 0, len(specificationAreaOrder))
	for _, area := range specificationAreaOrder {
		rows = append(rows, affectingRow(area, GradePass))
	}

	score, evidence, err := RateSpecification(terminalPassRun(), rows, nil)
	if err != nil {
		t.Fatalf("RateSpecification: %v", err)
	}

	assertCoverage(t, score, 8)
	assertGradeEq(t, score.Grade, GradePass)

	if len(evidence) != 8 {
		t.Fatalf("evidence = %d, want 8", len(evidence))
	}
}

func TestRateSpecification_IgnoresReportExchanges(t *testing.T) {
	t.Parallel()

	score, evidence, err := RateSpecification(terminalPassRun(), nil, []ReportExchange{{
		EndpointID: "discovery",
		Method:     "GET",
	}})
	if err != nil {
		t.Fatalf("RateSpecification: %v", err)
	}

	assertNilGrade(t, score.Grade)
	assertCoverage(t, score, 0)

	if evidence == nil || len(evidence) != 0 {
		t.Fatalf("evidence = %#v, want empty when only exchanges are supplied", evidence)
	}
}

func TestRateSpecification_PublicEvidenceOmitsExchangeID(t *testing.T) {
	t.Parallel()

	exchangeID := uint(99)
	rows := []EvidenceRow{{
		Area:         SpecificationAreaDiscovery,
		Step:         "fetch",
		ReasonCode:   "discovery_probed",
		Severity:     GradePass,
		AffectsGrade: true,
		ExchangeID:   &exchangeID,
	}}

	_, evidence, err := RateSpecification(terminalPassRun(), rows, nil)
	if err != nil {
		t.Fatalf("RateSpecification: %v", err)
	}

	if len(evidence) != 1 {
		t.Fatalf("evidence = %d, want 1", len(evidence))
	}

	raw := mustJSON(t, evidence)
	if strings.Contains(raw, "exchangeId") || strings.Contains(raw, "99") {
		t.Fatalf("public evidence leaked exchange identity: %s", raw)
	}
}

func TestRateSpecification_ReverseInviteMapsToSharing(t *testing.T) {
	t.Parallel()

	payload := "invite accepted"
	reverse := evidenceLegReverse
	rows := []EvidenceRow{{
		Leg:             &reverse,
		Area:            SpecificationAreaSharing,
		Step:            evidenceStepInviteAccepted,
		ReasonCode:      evidenceReasonReverseAccepted,
		Severity:        GradePass,
		AffectsGrade:    true,
		PayloadRedacted: &payload,
	}}

	score, evidence, err := RateSpecification(terminalPassRun(), rows, nil)
	if err != nil {
		t.Fatalf("RateSpecification: %v", err)
	}

	assertGradeEq(t, areaByName(score, SpecificationAreaSharing).Grade, GradePass)
	assertGradeEq(t, score.Grade, GradePass)

	if len(evidence) != 1 {
		t.Fatalf("evidence = %d, want 1", len(evidence))
	}

	if evidence[0].Area != SpecificationAreaSharing {
		t.Fatalf("area = %q, want %q", evidence[0].Area, SpecificationAreaSharing)
	}

	if evidence[0].ScoreArea != "" {
		t.Fatalf("scoreArea = %q, want empty when area already maps to itself", evidence[0].ScoreArea)
	}

	if evidence[0].Leg != evidenceLegReverse {
		t.Fatalf("leg = %q, want %q", evidence[0].Leg, evidenceLegReverse)
	}
}

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
