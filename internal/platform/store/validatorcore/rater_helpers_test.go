// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
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
