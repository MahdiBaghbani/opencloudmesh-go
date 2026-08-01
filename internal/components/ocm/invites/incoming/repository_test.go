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

// TestFindAcceptedForSender_RequiresNormalizedColumn verifies the
// bidirectional must-invite lookup fails closed: a row whose normalized sender
// host was never persisted never matches, even when user and host inputs
// would otherwise agree.
func TestFindAcceptedForSender_RequiresNormalizedColumn(t *testing.T) {
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

	// Acceptance without identity persistence leaves the normalized column empty.
	if err := repo.UpdateStatusForRecipientUserID(ctx, invite.ID, "user-a", invites.InviteStatusAccepted, nil); err != nil {
		t.Fatalf("UpdateStatusForRecipientUserID: %v", err)
	}

	if _, err := repo.FindAcceptedForSender(ctx, "user-a", "sender-user", "sender.example"); !errors.Is(err, invites.ErrInviteNotFound) {
		t.Errorf("FindAcceptedForSender with empty normalized column: got %v, want ErrInviteNotFound", err)
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
