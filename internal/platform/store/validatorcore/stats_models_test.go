// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import "testing"

func TestStatsSnapshot_ToStatsRaw(t *testing.T) {
	t.Parallel()

	pass := GradePass
	snap := StatsSnapshot{
		HostHash:               "abc",
		SessionKind:            SessionKindActiveFull,
		ReverseInviteExercised: true,
		Platform:               "Nextcloud",
		APIVersion:             "1.2.0",
		GradeDiscovery:         &pass,
		CreatedAt:              42,
	}

	raw := snap.ToStatsRaw()
	if raw.HostHash != snap.HostHash {
		t.Fatalf("host hash mismatch")
	}

	if !raw.ReverseInviteExercised {
		t.Fatal("expected reverse_invite_exercised true")
	}
}
