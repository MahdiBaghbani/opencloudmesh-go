package repos_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

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
		// Guard the app-level semantic: List() returns all invites regardless
		// of creator. Seed two invites with different CreatedByUserID values
		// and assert both appear in the result.
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
