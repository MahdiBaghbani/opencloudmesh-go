// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import "testing"

func TestMergeTerminalStatsOverlay_CopiesAreaGrades(t *testing.T) {
	t.Parallel()

	pass := GradePass
	warn := GradeWarn

	base := StatsSnapshot{
		HostHash:    "hash-a",
		SessionKind: SessionKindPassiveOnly,
		CreatedAt:   100,
	}
	overlay := StatsSnapshot{
		Platform:               "Nextcloud",
		GradeDiscovery:         &pass,
		GradeTLS:               &warn,
		GradeCapability:        &pass,
		ReverseInviteExercised: true,
	}

	mergeTerminalStatsOverlay(&base, &overlay)

	if base.Platform != "Nextcloud" {
		t.Fatalf("platform = %q, want Nextcloud", base.Platform)
	}

	if base.GradeDiscovery == nil || *base.GradeDiscovery != GradePass {
		t.Fatalf("grade_discovery = %v, want pass", base.GradeDiscovery)
	}

	if base.GradeTLS == nil || *base.GradeTLS != GradeWarn {
		t.Fatalf("grade_tls = %v, want warn", base.GradeTLS)
	}

	if !base.ReverseInviteExercised {
		t.Fatal("expected reverse_invite_exercised from overlay")
	}

	if base.HostHash != "hash-a" {
		t.Fatalf("host_hash = %q, want preserved base value", base.HostHash)
	}
}

func TestStatsSnapshotFromTestRun_UsesOverlayGrades(t *testing.T) {
	t.Parallel()

	pass := GradePass
	row := &TestRun{
		SessionKind: SessionKindPassiveOnly,
	}
	overlay := &StatsSnapshot{GradeDiscovery: &pass}

	snap := statsSnapshotFromTestRun(row, "hash-a", 200, overlay)

	if snap.GradeDiscovery == nil || *snap.GradeDiscovery != GradePass {
		t.Fatalf("grade_discovery = %v, want pass", snap.GradeDiscovery)
	}

	if !DeriveHealthySnapshot(snap) {
		t.Fatal("expected healthy snapshot from overlay grade")
	}
}
