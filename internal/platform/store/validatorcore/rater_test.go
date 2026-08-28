// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"strings"
	"testing"
)

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
