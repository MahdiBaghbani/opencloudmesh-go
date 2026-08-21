// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func TestFillSnapshotGradesFromRating_UsesEvidenceRows(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-rating-fill"

	seedTerminalStatsRun(t, core, runID, now)
	seedEvidenceRow(t, core, runID, evidenceLegPassive, SpecificationAreaDiscovery, "fetch", "discovery_ok", GradePass, true)
	seedEvidenceRow(t, core, runID, evidenceLegPassive, SpecificationAreaTLS, "handshake", "cert_expiry_near", "important", true)
	seedEvidenceRow(t, core, runID, evidenceLegPassive, SpecificationAreaJWKS, "fetch", "jwks_fail", GradeFail, true)

	if err := core.persistTerminalStats(ctx, runID); err != nil {
		t.Fatalf("persist: %v", err)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.GradeDiscovery == nil || *raw.GradeDiscovery != GradePass {
		t.Fatalf("grade_discovery = %v, want pass", raw.GradeDiscovery)
	}

	if raw.GradeTLS == nil || *raw.GradeTLS != GradeWarn {
		t.Fatalf("grade_tls = %v, want warn", raw.GradeTLS)
	}

	if raw.GradeJWKS == nil || *raw.GradeJWKS != GradeFail {
		t.Fatalf("grade_jwks = %v, want fail from evidence", raw.GradeJWKS)
	}
}

func TestFillSnapshotGradesFromRating_EvidenceDeterminesGrade(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-rating-evidence"

	seedTerminalStatsRun(t, core, runID, now)
	seedEvidenceRow(t, core, runID, evidenceLegPassive, SpecificationAreaDiscovery, "fetch", "discovery_missing", GradeFail, true)

	if err := core.persistTerminalStats(ctx, runID); err != nil {
		t.Fatalf("persist: %v", err)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.GradeDiscovery == nil || *raw.GradeDiscovery != GradeFail {
		t.Fatalf("grade_discovery = %v, want fail from evidence", raw.GradeDiscovery)
	}
}

func TestFillSnapshotGradesFromRating_ReverseInviteSetsSharing(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-rating-reverse"

	seedTerminalStatsRun(t, core, runID, now)
	seedEvidenceRow(
		t,
		core,
		runID,
		evidenceLegReverse,
		SpecificationAreaSharing,
		evidenceStepInviteAccepted,
		evidenceReasonReverseAccepted,
		GradePass,
		true,
	)

	if err := core.persistTerminalStats(ctx, runID); err != nil {
		t.Fatalf("persist: %v", err)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.GradeSharing == nil || *raw.GradeSharing != GradePass {
		t.Fatalf("grade_sharing = %v, want pass from reverse invite", raw.GradeSharing)
	}

	if !raw.ReverseInviteExercised {
		t.Fatal("reverse_invite_exercised = false, want true")
	}
}

func TestFillSnapshotGradesFromRating_NonReverseLegDoesNotSetReverseInvite(t *testing.T) {
	t.Parallel()

	for _, leg := range []string{evidenceLegPassive, evidenceLegForward} {
		t.Run(leg, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			core.SetStatsHostHasher(testStatsHostHasher(t))
			ctx := t.Context()
			now := time.Now().Unix()
			runID := "run-rating-cross-leg-" + leg

			seedTerminalStatsRun(t, core, runID, now)
			seedEvidenceRow(
				t,
				core,
				runID,
				leg,
				SpecificationAreaSharing,
				evidenceStepInviteAccepted,
				evidenceReasonReverseAccepted,
				GradePass,
				true,
			)

			if err := core.persistTerminalStats(ctx, runID); err != nil {
				t.Fatalf("persist: %v", err)
			}

			var raw StatsRaw
			if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
				t.Fatalf("load stats_raw: %v", err)
			}

			if raw.ReverseInviteExercised {
				t.Fatalf("reverse_invite_exercised = true from %s evidence, want false", leg)
			}

			if raw.GradeSharing != nil {
				t.Fatalf("grade_sharing = %v from %s evidence, want nil", raw.GradeSharing, leg)
			}
		})
	}
}
