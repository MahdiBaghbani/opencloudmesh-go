// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import "testing"

func TestStatsSnapshotFromTestRun_CopiesPersistedPlatform(t *testing.T) {
	t.Parallel()

	platform := "Nextcloud"
	apiVersion := "1.4.0"
	row := &TestRun{
		Platform:   &platform,
		APIVersion: &apiVersion,
	}

	snap := statsSnapshotFromTestRun(row, "hash-a", 200)

	if snap.Platform != platform {
		t.Fatalf("platform = %q, want %q", snap.Platform, platform)
	}

	if snap.APIVersion != apiVersion {
		t.Fatalf("api_version = %q, want %q", snap.APIVersion, apiVersion)
	}

	if snap.HostHash != "hash-a" {
		t.Fatalf("host_hash = %q, want hash-a", snap.HostHash)
	}

	if snap.CreatedAt != 200 {
		t.Fatalf("created_at = %d, want 200", snap.CreatedAt)
	}

	if snap.GradeDiscovery != nil {
		t.Fatalf("grade_discovery = %v, want nil until evidence fill", snap.GradeDiscovery)
	}
}
