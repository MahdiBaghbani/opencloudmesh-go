// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

func seedReverseInviteRun(t *testing.T, core *Core, runID, state string) {
	t.Helper()

	now := time.Now().Unix()

	if err := core.DB().WithContext(t.Context()).Create(&TestRun{
		TestRunID:      runID,
		IsActive:       true,
		State:          state,
		TargetOrigin:   "https://peer.example",
		TargetHost:     "peer.example",
		DiscoveryURL:   "https://peer.example/.well-known/ocm",
		ManifestSchema: "ocm-validator-manifest/v1",
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed active run %s: %v", runID, err)
	}
}

func sampleOutgoingMint(inviteID, token, createdBy string) OutgoingInviteMint {
	now := time.Now().Unix()

	return OutgoingInviteMint{
		ID:              inviteID,
		Token:           token,
		ProviderFQDN:    "local.example",
		InviteString:    "invite-string-" + inviteID,
		CreatedByUserID: createdBy,
		Status:          "pending",
		CreatedAt:       now,
		ExpiresAt:       now + 3600,
	}
}

func countOutgoingInvites(t *testing.T, core *Core) int {
	t.Helper()

	var count int64
	if err := core.DB().WithContext(t.Context()).
		Model(&store.OutgoingInvite{}).
		Count(&count).Error; err != nil {
		t.Fatalf("count outgoing invites: %v", err)
	}

	return int(count)
}

func requireNoS1Claim(t *testing.T, core *Core, runID string) {
	t.Helper()

	run, err := core.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.S1ClaimedAt != nil {
		t.Fatalf("s1_claimed_at = %v, want nil", run.S1ClaimedAt)
	}
}

func countIncomingInviteCorrelations(t *testing.T, core *Core, runID string) int {
	t.Helper()

	var count int64
	if err := core.DB().WithContext(t.Context()).
		Model(&ShareCorrelation{}).
		Where("test_run_id = ? AND role = ?", runID, RoleIncomingInvite).
		Count(&count).Error; err != nil {
		t.Fatalf("count incoming invite correlations: %v", err)
	}

	return int(count)
}

func countShareCorrelations(t *testing.T, core *Core, runID string) int {
	t.Helper()

	var count int64
	if err := core.DB().WithContext(t.Context()).
		Model(&ShareCorrelation{}).
		Where("test_run_id = ?", runID).
		Count(&count).Error; err != nil {
		t.Fatalf("count share correlations: %v", err)
	}

	return int(count)
}
