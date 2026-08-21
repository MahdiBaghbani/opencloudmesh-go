// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func seedCapabilityFileOpenedEvidence(t *testing.T, core *Core, runID, reason string) {
	t.Helper()

	if err := core.DB().WithContext(t.Context()).Create(&EvidenceRow{
		TestRunID:    runID,
		Area:         "capability",
		Step:         "file_opened",
		ReasonCode:   reason,
		Severity:     GradePass,
		AffectsGrade: true,
		CreatedAt:    time.Now().Unix(),
	}).Error; err != nil {
		t.Fatalf("seed evidence row: %v", err)
	}
}

func TestHealForwardSharePresence_AdvancesOnExistingEvidence(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	runID := "run-fwd-heal"

	seedForwardRun(t, core, runID, StateForwardShareSent)

	// The evidence row already exists, so the seam's insert-gated advance can
	// never fire; the presence heal must still move the run.
	seedCapabilityFileOpenedEvidence(t, core, runID, "webdav_get")

	if err := core.HealForwardSharePresence(t.Context(), runID); err != nil {
		t.Fatalf("heal: %v", err)
	}

	requireState(t, core, runID, StateCapabilityExercise)
}

func TestHealForwardSharePresence_NoEvidenceLeavesState(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	runID := "run-fwd-heal-none"

	seedForwardRun(t, core, runID, StateForwardShareSent)

	if err := core.HealForwardSharePresence(t.Context(), runID); err != nil {
		t.Fatalf("heal: %v", err)
	}

	requireState(t, core, runID, StateForwardShareSent)
}

func TestHealForwardSharePresence_LeavesLaterStatesAlone(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	runID := "run-fwd-heal-late"

	seedForwardRun(t, core, runID, StateCapabilityExercise)
	seedCapabilityFileOpenedEvidence(t, core, runID, "token_exchange")

	if err := core.HealForwardSharePresence(t.Context(), runID); err != nil {
		t.Fatalf("heal: %v", err)
	}

	requireState(t, core, runID, StateCapabilityExercise)
}
