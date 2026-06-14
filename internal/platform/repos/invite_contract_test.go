package repos_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

// runIncomingInviteRepoContract verifies CRUD, list, recipient-scope enforcement,
// auto-fill, and ErrInviteNotFound sentinel for the IncomingInviteRepo
// interface.
func runIncomingInviteRepoContract(t *testing.T, r *repos.Repos) {
	t.Helper()
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		invite := &invitesinbox.IncomingInvite{
			ID:              "ct-in-inv-1",
			Token:           "ct-in-token-1",
			InviteString:    "b64ct-in",
			SenderFQDN:      "ct.sender.invite.example",
			RecipientUserID: "ct-recipient-1",
			Status:          invites.InviteStatusPending,
			ReceivedAt:      time.Unix(time.Now().Unix(), 0).UTC(),
		}
		if err := r.IncomingInvites.Create(ctx, invite); err != nil {
			t.Fatalf("Create: %v", err)
		}

		got, err := r.IncomingInvites.GetByIDForRecipientUserID(ctx, invite.ID, invite.RecipientUserID)
		if err != nil {
			t.Fatalf("GetByIDForRecipientUserID: %v", err)
		}
		if got.Token != invite.Token {
			t.Errorf("Token: got %q, want %q", got.Token, invite.Token)
		}

		got, err = r.IncomingInvites.GetByTokenForRecipientUserID(ctx, invite.Token, invite.RecipientUserID)
		if err != nil {
			t.Fatalf("GetByTokenForRecipientUserID: %v", err)
		}
		if got.ID != invite.ID {
			t.Errorf("ID: got %q, want %q", got.ID, invite.ID)
		}

		if err := r.IncomingInvites.UpdateStatusForRecipientUserID(
			ctx, invite.ID, invite.RecipientUserID, invites.InviteStatusAccepted,
		); err != nil {
			t.Fatalf("UpdateStatusForRecipientUserID: %v", err)
		}
		got, err = r.IncomingInvites.GetByIDForRecipientUserID(ctx, invite.ID, invite.RecipientUserID)
		if err != nil {
			t.Fatalf("GetByIDForRecipientUserID after update: %v", err)
		}
		if got.Status != invites.InviteStatusAccepted {
			t.Errorf("Status after update: got %q, want accepted", got.Status)
		}

		if err := r.IncomingInvites.DeleteForRecipientUserID(ctx, invite.ID, invite.RecipientUserID); err != nil {
			t.Fatalf("DeleteForRecipientUserID: %v", err)
		}
		_, err = r.IncomingInvites.GetByIDForRecipientUserID(ctx, invite.ID, invite.RecipientUserID)
		if !errors.Is(err, invites.ErrInviteNotFound) {
			t.Errorf("GetByIDForRecipientUserID after delete: expected ErrInviteNotFound, got %v", err)
		}
	})

	t.Run("ListByRecipientUserID", func(t *testing.T) {
		invite := &invitesinbox.IncomingInvite{
			ID:              "ct-list-in-inv-1",
			Token:           "ct-list-in-token-1",
			InviteString:    "b64ct-list-in",
			SenderFQDN:      "ct.list.sender.invite.example",
			RecipientUserID: "ct-list-recipient-user",
			Status:          invites.InviteStatusPending,
			ReceivedAt:      time.Unix(time.Now().Unix(), 0).UTC(),
		}
		if err := r.IncomingInvites.Create(ctx, invite); err != nil {
			t.Fatalf("Create: %v", err)
		}

		all, err := r.IncomingInvites.ListByRecipientUserID(ctx, invite.RecipientUserID)
		if err != nil {
			t.Fatalf("ListByRecipientUserID: %v", err)
		}
		found := false
		for _, inv := range all {
			if inv.ID == invite.ID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ListByRecipientUserID: created invite %q not found in result", invite.ID)
		}

		others, err := r.IncomingInvites.ListByRecipientUserID(ctx, "ct-another-user-entirely")
		if err != nil {
			t.Fatalf("ListByRecipientUserID other user: %v", err)
		}
		for _, inv := range others {
			if inv.ID == invite.ID {
				t.Errorf("ListByRecipientUserID: invite %q leaked to other user", invite.ID)
			}
		}
	})

	t.Run("EnforcesRecipientScope", func(t *testing.T) {
		invite := &invitesinbox.IncomingInvite{
			ID:              "ct-scope-in-inv-1",
			Token:           "ct-scope-in-token-1",
			InviteString:    "b64ct-scope",
			SenderFQDN:      "ct.scope.sender.invite.example",
			RecipientUserID: "ct-scope-inv-owner",
			Status:          invites.InviteStatusPending,
			ReceivedAt:      time.Unix(time.Now().Unix(), 0).UTC(),
		}
		if err := r.IncomingInvites.Create(ctx, invite); err != nil {
			t.Fatalf("Create: %v", err)
		}

		_, err := r.IncomingInvites.GetByIDForRecipientUserID(ctx, invite.ID, "ct-inv-wrong-user")
		if !errors.Is(err, invites.ErrInviteNotFound) {
			t.Errorf("GetByIDForRecipientUserID wrong user: expected ErrInviteNotFound, got %v", err)
		}

		_, err = r.IncomingInvites.GetByTokenForRecipientUserID(ctx, invite.Token, "ct-inv-wrong-user")
		if !errors.Is(err, invites.ErrInviteNotFound) {
			t.Errorf("GetByTokenForRecipientUserID wrong user: expected ErrInviteNotFound, got %v", err)
		}

		err = r.IncomingInvites.UpdateStatusForRecipientUserID(
			ctx, invite.ID, "ct-inv-wrong-user", invites.InviteStatusAccepted,
		)
		if !errors.Is(err, invites.ErrInviteNotFound) {
			t.Errorf("UpdateStatusForRecipientUserID wrong user: expected ErrInviteNotFound, got %v", err)
		}

		err = r.IncomingInvites.DeleteForRecipientUserID(ctx, invite.ID, "ct-inv-wrong-user")
		if !errors.Is(err, invites.ErrInviteNotFound) {
			t.Errorf("DeleteForRecipientUserID wrong user: expected ErrInviteNotFound, got %v", err)
		}
	})

	t.Run("AutoFill", func(t *testing.T) {
		invite := &invitesinbox.IncomingInvite{
			Token:           "ct-autofill-in-token",
			InviteString:    "b64ct-autofill-in",
			SenderFQDN:      "ct.autofill.sender.invite.example",
			RecipientUserID: "ct-autofill-in-recipient",
		}
		if err := r.IncomingInvites.Create(ctx, invite); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if invite.ID == "" {
			t.Error("ID not auto-filled after Create")
		}
		if invite.ReceivedAt.IsZero() {
			t.Error("ReceivedAt not auto-filled after Create")
		}
		if invite.Status == "" {
			t.Error("Status not auto-filled after Create")
		}
	})

	t.Run("IDNotFoundSentinel", func(t *testing.T) {
		_, err := r.IncomingInvites.GetByIDForRecipientUserID(ctx, "ct-in-missing-invite-id", "any-user")
		if !errors.Is(err, invites.ErrInviteNotFound) {
			t.Errorf("GetByIDForRecipientUserID nonexistent: expected ErrInviteNotFound, got %v", err)
		}
	})
}

// runOutgoingInviteRepoContract verifies CRUD, list, auto-fill, token/ID
// sentinel behaviour for the OutgoingInviteRepo interface.
func runOutgoingInviteRepoContract(t *testing.T, r *repos.Repos) {
	t.Helper()
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		now := time.Unix(time.Now().Unix(), 0).UTC()
		invite := &invitesoutgoing.OutgoingInvite{
			ID:              "ct-out-inv-1",
			Token:           "ct-out-token-1",
			ProviderFQDN:    "ct.provider.example",
			InviteString:    "b64ct-out",
			RecipientEmail:  "alice@ct.example",
			CreatedByUserID: "ct-creator-1",
			CreatedAt:       now,
			ExpiresAt:       now.Add(24 * time.Hour),
			Status:          invites.InviteStatusPending,
		}
		if err := r.OutgoingInvites.Create(ctx, invite); err != nil {
			t.Fatalf("Create: %v", err)
		}

		got, err := r.OutgoingInvites.GetByID(ctx, invite.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.Token != invite.Token {
			t.Errorf("Token: got %q, want %q", got.Token, invite.Token)
		}

		got, err = r.OutgoingInvites.GetByToken(ctx, invite.Token)
		if err != nil {
			t.Fatalf("GetByToken: %v", err)
		}
		if got.ID != invite.ID {
			t.Errorf("GetByToken ID: got %q, want %q", got.ID, invite.ID)
		}

		if err := r.OutgoingInvites.UpdateStatus(
			ctx, invite.ID, invites.InviteStatusAccepted, "ct-acceptor-1",
		); err != nil {
			t.Fatalf("UpdateStatus: %v", err)
		}
		got, err = r.OutgoingInvites.GetByID(ctx, invite.ID)
		if err != nil {
			t.Fatalf("GetByID after UpdateStatus: %v", err)
		}
		if got.Status != invites.InviteStatusAccepted {
			t.Errorf("Status after update: got %q, want accepted", got.Status)
		}
		if got.AcceptedBy != "ct-acceptor-1" {
			t.Errorf("AcceptedBy: got %q, want ct-acceptor-1", got.AcceptedBy)
		}
		if got.AcceptedAt == nil {
			t.Error("AcceptedAt: expected non-nil after acceptance")
		}
	})

	t.Run("List", func(t *testing.T) {
		now := time.Unix(time.Now().Unix(), 0).UTC()
		inviteA := &invitesoutgoing.OutgoingInvite{
			ID:              "ct-list-out-inv-1",
			Token:           "ct-list-out-token-1",
			ProviderFQDN:    "ct.list.provider.example",
			InviteString:    "b64ct-list-out-1",
			CreatedByUserID: "ct-list-creator-A",
			CreatedAt:       now,
			ExpiresAt:       now.Add(24 * time.Hour),
			Status:          invites.InviteStatusPending,
		}
		inviteB := &invitesoutgoing.OutgoingInvite{
			ID:              "ct-list-out-inv-2",
			Token:           "ct-list-out-token-2",
			ProviderFQDN:    "ct.list.provider.example",
			InviteString:    "b64ct-list-out-2",
			CreatedByUserID: "ct-list-creator-B",
			CreatedAt:       now,
			ExpiresAt:       now.Add(24 * time.Hour),
			Status:          invites.InviteStatusPending,
		}
		if err := r.OutgoingInvites.Create(ctx, inviteA); err != nil {
			t.Fatalf("Create inviteA: %v", err)
		}
		if err := r.OutgoingInvites.Create(ctx, inviteB); err != nil {
			t.Fatalf("Create inviteB: %v", err)
		}

		all, err := r.OutgoingInvites.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		foundA, foundB := false, false
		for _, inv := range all {
			switch inv.ID {
			case inviteA.ID:
				foundA = true
			case inviteB.ID:
				foundB = true
			}
		}
		if !foundA {
			t.Errorf("List: invite %q (creator-A) not found; List must return all invites, not creator-filtered", inviteA.ID)
		}
		if !foundB {
			t.Errorf("List: invite %q (creator-B) not found; List must return all invites, not creator-filtered", inviteB.ID)
		}
	})

	t.Run("AutoFill", func(t *testing.T) {
		now := time.Unix(time.Now().Unix(), 0).UTC()
		invite := &invitesoutgoing.OutgoingInvite{
			Token:        "ct-autofill-out-token",
			ProviderFQDN: "ct.autofill.provider.example",
			InviteString: "b64ct-autofill-out",
			CreatedAt:    now,
			ExpiresAt:    now.Add(24 * time.Hour),
		}
		if err := r.OutgoingInvites.Create(ctx, invite); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if invite.ID == "" {
			t.Error("ID not auto-filled after Create")
		}
		if invite.Status == "" {
			t.Error("Status not auto-filled after Create")
		}
	})

	t.Run("TokenSentinel", func(t *testing.T) {
		_, err := r.OutgoingInvites.GetByToken(ctx, "ct-out-missing-token")
		if !errors.Is(err, invites.ErrTokenNotFound) {
			t.Errorf("GetByToken nonexistent: expected ErrTokenNotFound, got %v", err)
		}
	})

	t.Run("IDNotFoundSentinel", func(t *testing.T) {
		_, err := r.OutgoingInvites.GetByID(ctx, "ct-out-missing-invite-id")
		if !errors.Is(err, invites.ErrInviteNotFound) {
			t.Errorf("GetByID nonexistent: expected ErrInviteNotFound, got %v", err)
		}
	})
}
