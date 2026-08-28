// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
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

func jwksProbeFact(runID, severity string) ApplyEvidenceFactInput {
	return ApplyEvidenceFactInput{
		TestRunID:    runID,
		Area:         SpecificationAreaJWKS,
		Step:         "fetch",
		ReasonCode:   "jwks_probed",
		Severity:     severity,
		AffectsGrade: true,
		Leg:          evidenceLegPassive,
	}
}

func mustLoadEvidence(t *testing.T, core *Core, runID string) EvidenceRow {
	t.Helper()

	var row EvidenceRow
	if err := core.DB().WithContext(t.Context()).Where("test_run_id = ?", runID).First(&row).Error; err != nil {
		t.Fatalf("load evidence: %v", err)
	}

	return row
}
