// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package outgoing_test

import (
	"context"
	"errors"
	"testing"
	"time"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
)

// TestFindAcceptedForRecipient_RequiresNormalizedColumn verifies the
// must-invite lookup fails closed: a row accepted without identity persistence
// (empty normalized provider column) never matches.
func TestFindAcceptedForRecipient_RequiresNormalizedColumn(t *testing.T) {
	repo := tsrepos.OpenMemory(t).OutgoingInvites
	ctx := context.Background()

	invite := &outgoing.OutgoingInvite{
		Token:           "tok-no-normalized",
		ProviderFQDN:    "receiver.example",
		CreatedByUserID: "sender-user",
		Status:          invites.InviteStatusPending,
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	if err := repo.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Acceptance with only the user identity leaves the normalized column empty.
	acceptance := &outgoing.Acceptance{UserID: "recipient-user"}
	if err := repo.UpdateStatus(ctx, invite.ID, invites.InviteStatusAccepted, acceptance); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	if _, err := repo.FindAcceptedForRecipient(ctx, "sender-user", "recipient-user", "receiver.example"); !errors.Is(err, invites.ErrInviteNotFound) {
		t.Errorf("FindAcceptedForRecipient with empty normalized column: got %v, want ErrInviteNotFound", err)
	}
}

// TestFindAcceptedForRecipient_MatchesPersistedIdentity covers the positive
// path: an acceptance carrying recipient identity is findable by user and
// normalized host.
func TestFindAcceptedForRecipient_MatchesPersistedIdentity(t *testing.T) {
	repo := tsrepos.OpenMemory(t).OutgoingInvites
	ctx := context.Background()

	invite := &outgoing.OutgoingInvite{
		Token:           "tok-with-identity",
		ProviderFQDN:    "receiver.example",
		CreatedByUserID: "sender-user",
		Status:          invites.InviteStatusPending,
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	if err := repo.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	acceptance := &outgoing.Acceptance{
		ProviderFQDN:           "receiver.example",
		UserID:                 "recipient-user",
		ProviderFQDNNormalized: "receiver.example",
	}
	if err := repo.UpdateStatus(ctx, invite.ID, invites.InviteStatusAccepted, acceptance); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	found, err := repo.FindAcceptedForRecipient(ctx, "sender-user", "recipient-user", "receiver.example")
	if err != nil {
		t.Fatalf("FindAcceptedForRecipient: %v", err)
	}

	if found.ID != invite.ID {
		t.Errorf("found ID = %q, want %q", found.ID, invite.ID)
	}
}
