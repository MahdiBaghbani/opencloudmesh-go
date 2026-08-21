// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func seedGradedExchange(
	t *testing.T,
	core *Core,
	runID, endpoint, grade string,
	seq int,
) {
	t.Helper()

	g := grade
	row := &ReportExchange{
		TestRunID:  runID,
		Seq:        seq,
		CapturedAt: int64(seq),
		Direction:  "out",
		EndpointID: endpoint,
		Method:     "GET",
		URL:        "https://peer.example/" + endpoint,
		Grade:      &g,
		CreatedAt:  int64(seq),
	}

	if err := core.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed exchange: %v", err)
	}
}

func TestFillSnapshotGradesFromRating_UsesEvidenceAndExchanges(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-rating-fill"

	seedTerminalStatsRun(t, core, runID, now)
	seedEvidenceRow(t, core, runID, SpecificationAreaDiscovery, "fetch", "discovery_ok", GradePass, true)
	seedEvidenceRow(t, core, runID, SpecificationAreaTLS, "handshake", "cert_expiry_near", "important", true)
	seedGradedExchange(t, core, runID, endpointJWKS, GradeFail, 1)

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
		t.Fatalf("grade_jwks = %v, want fail from graded exchange", raw.GradeJWKS)
	}
}

func TestFillSnapshotGradesFromRating_OverlayWins(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-rating-overlay"
	pass := GradePass

	seedTerminalStatsRun(t, core, runID, now)
	seedEvidenceRow(t, core, runID, SpecificationAreaDiscovery, "fetch", "discovery_missing", GradeFail, true)
	seedGradedExchange(t, core, runID, endpointDiscovery, GradeFail, 1)
	core.SetTerminalStatsSnapshot(runID, StatsSnapshot{GradeDiscovery: &pass})

	if err := core.persistTerminalStats(ctx, runID); err != nil {
		t.Fatalf("persist: %v", err)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.GradeDiscovery == nil || *raw.GradeDiscovery != GradePass {
		t.Fatalf("grade_discovery = %v, want pass from overlay", raw.GradeDiscovery)
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
		evidenceAreaReverseInvite,
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
