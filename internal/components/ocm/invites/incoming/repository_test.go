// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"context"
	"errors"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
)

// TestCreate_RejectsAcceptedWithoutIdentity verifies the create-time guard:
// an invite created directly in accepted status must carry the full sender
// identity.
func TestCreate_RejectsAcceptedWithoutIdentity(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites
	ctx := context.Background()

	invite := &incoming.IncomingInvite{
		Token:           "tok-create-accepted",
		SenderFQDN:      "sender.example",
		RecipientUserID: "user-a",
		Status:          invites.InviteStatusAccepted,
	}
	if err := repo.Create(ctx, invite); !errors.Is(err, invites.ErrInvalidCreateStatus) {
		t.Errorf("Create accepted without identity: got %v, want ErrInvalidCreateStatus", err)
	}
}

// TestUpdateStatusForRecipientUserID_RejectsAcceptedWithoutIdentity verifies
// the acceptance identity invariant fails closed: an accepted update carrying
// no sender identity is rejected instead of persisting a row the must-invite
// lookup could never match.
func TestUpdateStatusForRecipientUserID_RejectsAcceptedWithoutIdentity(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites
	ctx := context.Background()

	invite := &incoming.IncomingInvite{
		Token:           "tok-no-normalized",
		SenderFQDN:      "Sender.Example",
		RecipientUserID: "user-a",
		Status:          invites.InviteStatusPending,
	}
	if err := repo.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.UpdateStatusForRecipientUserID(ctx, invite.ID, "user-a", invites.InviteStatusAccepted, nil); !errors.Is(err, invites.ErrInvalidAcceptedIdentity) {
		t.Errorf("UpdateStatusForRecipientUserID accepted without identity: got %v, want ErrInvalidAcceptedIdentity", err)
	}
}

// TestFindAcceptedForSender_MatchesPersistedIdentity covers the positive path:
// an acceptance carrying sender identity is findable by user and normalized
// host.
func TestFindAcceptedForSender_MatchesPersistedIdentity(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites
	ctx := context.Background()

	invite := &incoming.IncomingInvite{
		Token:           "tok-with-identity",
		SenderFQDN:      "sender.example",
		RecipientUserID: "user-a",
		Status:          invites.InviteStatusPending,
	}
	if err := repo.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	acceptance := &incoming.Acceptance{
		UserID:                 "sender-user",
		ProviderFQDN:           "sender.example",
		ProviderFQDNNormalized: "sender.example",
	}
	if err := repo.UpdateStatusForRecipientUserID(ctx, invite.ID, "user-a", invites.InviteStatusAccepted, acceptance); err != nil {
		t.Fatalf("UpdateStatusForRecipientUserID: %v", err)
	}

	found, err := repo.FindAcceptedForSender(ctx, "user-a", "sender-user", "sender.example")
	if err != nil {
		t.Fatalf("FindAcceptedForSender: %v", err)
	}

	if found.ID != invite.ID {
		t.Errorf("found ID = %q, want %q", found.ID, invite.ID)
	}
}
