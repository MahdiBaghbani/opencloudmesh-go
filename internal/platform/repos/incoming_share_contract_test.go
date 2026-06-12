package repos_test

import (
	"context"
	"errors"
	"testing"
	"time"

	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

// runIncomingShareRepoContract verifies CRUD, list, recipient-scope guard,
// auto-fill, and ErrShareNotFound sentinel for the IncomingShareRepo interface.
func runIncomingShareRepoContract(t *testing.T, r *repos.Repos) {
	t.Helper()
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		share := &sharesinbox.IncomingShare{
			ShareID:         "ct-in-s1",
			ProviderID:      "ct-in-p1",
			SenderHost:      "ct.sender.example",
			ShareWith:       "bob",
			Name:            "ct-inshare",
			ResourceType:    "file",
			Permissions:     []string{"read"},
			Status:          sharesinbox.ShareStatusPending,
			RecipientUserID: "ct-user-1",
			CreatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
			UpdatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
		}
		if err := r.IncomingShares.Create(ctx, share); err != nil {
			t.Fatalf("Create: %v", err)
		}

		got, err := r.IncomingShares.GetByIDForRecipientUserID(ctx, share.ShareID, share.RecipientUserID)
		if err != nil {
			t.Fatalf("GetByIDForRecipientUserID: %v", err)
		}
		if got.ShareID != share.ShareID {
			t.Errorf("ShareID: got %q, want %q", got.ShareID, share.ShareID)
		}

		got, err = r.IncomingShares.GetByProviderID(ctx, share.SenderHost, share.ProviderID)
		if err != nil {
			t.Fatalf("GetByProviderID: %v", err)
		}
		if got.ShareID != share.ShareID {
			t.Errorf("GetByProviderID ShareID: got %q, want %q", got.ShareID, share.ShareID)
		}

		if err := r.IncomingShares.UpdateStatusForRecipientUserID(
			ctx, share.ShareID, share.RecipientUserID, sharesinbox.ShareStatusAccepted,
		); err != nil {
			t.Fatalf("UpdateStatusForRecipientUserID: %v", err)
		}
		got, err = r.IncomingShares.GetByIDForRecipientUserID(ctx, share.ShareID, share.RecipientUserID)
		if err != nil {
			t.Fatalf("GetByIDForRecipientUserID after status update: %v", err)
		}
		if got.Status != sharesinbox.ShareStatusAccepted {
			t.Errorf("Status after update: got %q, want accepted", got.Status)
		}

		if err := r.IncomingShares.DeleteForRecipientUserID(ctx, share.ShareID, share.RecipientUserID); err != nil {
			t.Fatalf("DeleteForRecipientUserID: %v", err)
		}
		_, err = r.IncomingShares.GetByIDForRecipientUserID(ctx, share.ShareID, share.RecipientUserID)
		if !errors.Is(err, sharesinbox.ErrShareNotFound) {
			t.Errorf("GetByIDForRecipientUserID after delete: expected ErrShareNotFound, got %v", err)
		}
	})

	t.Run("ListByRecipientUserID", func(t *testing.T) {
		share := &sharesinbox.IncomingShare{
			ShareID:         "ct-list-in-s1",
			ProviderID:      "ct-list-in-p1",
			SenderHost:      "ct.list.sender.example",
			ShareWith:       "listuser",
			Name:            "ct-list-inshare",
			ResourceType:    "file",
			Permissions:     []string{"read"},
			Status:          sharesinbox.ShareStatusPending,
			RecipientUserID: "ct-list-user",
			CreatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
			UpdatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
		}
		if err := r.IncomingShares.Create(ctx, share); err != nil {
			t.Fatalf("Create: %v", err)
		}

		shares, err := r.IncomingShares.ListByRecipientUserID(ctx, share.RecipientUserID)
		if err != nil {
			t.Fatalf("ListByRecipientUserID: %v", err)
		}
		found := false
		for _, s := range shares {
			if s.ShareID == share.ShareID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ListByRecipientUserID: created share %q not found in result", share.ShareID)
		}

		others, err := r.IncomingShares.ListByRecipientUserID(ctx, "ct-other-user-entirely")
		if err != nil {
			t.Fatalf("ListByRecipientUserID other user: %v", err)
		}
		for _, s := range others {
			if s.ShareID == share.ShareID {
				t.Errorf("ListByRecipientUserID: share %q leaked to other user", share.ShareID)
			}
		}
	})

	t.Run("RecipientScopeGuard", func(t *testing.T) {
		share := &sharesinbox.IncomingShare{
			ShareID:         "ct-scope-in-s1",
			ProviderID:      "ct-scope-in-p1",
			SenderHost:      "ct.scope.sender.example",
			ShareWith:       "scopeuser",
			Name:            "ct-scope-inshare",
			ResourceType:    "file",
			Permissions:     []string{"read"},
			Status:          sharesinbox.ShareStatusPending,
			RecipientUserID: "ct-scope-owner",
			CreatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
			UpdatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
		}
		if err := r.IncomingShares.Create(ctx, share); err != nil {
			t.Fatalf("Create: %v", err)
		}

		_, err := r.IncomingShares.GetByIDForRecipientUserID(ctx, share.ShareID, "ct-wrong-user")
		if !errors.Is(err, sharesinbox.ErrShareNotFound) {
			t.Errorf("GetByIDForRecipientUserID wrong user: expected ErrShareNotFound, got %v", err)
		}

		err = r.IncomingShares.UpdateStatusForRecipientUserID(
			ctx, share.ShareID, "ct-wrong-user", sharesinbox.ShareStatusAccepted,
		)
		if !errors.Is(err, sharesinbox.ErrShareNotFound) {
			t.Errorf("UpdateStatusForRecipientUserID wrong user: expected ErrShareNotFound, got %v", err)
		}

		err = r.IncomingShares.DeleteForRecipientUserID(ctx, share.ShareID, "ct-wrong-user")
		if !errors.Is(err, sharesinbox.ErrShareNotFound) {
			t.Errorf("DeleteForRecipientUserID wrong user: expected ErrShareNotFound, got %v", err)
		}
	})

	t.Run("ProviderIDScopeGuard", func(t *testing.T) {
		// Guard the sender-scoped lookup semantic: GetByProviderID(senderHost,
		// providerID) must distinguish between two shares that share the same
		// ProviderID but originate from different senders.
		shareA := &sharesinbox.IncomingShare{
			ShareID:         "ct-pscope-in-s-A",
			ProviderID:      "ct-pscope-p1",
			SenderHost:      "ct.sender-a.pscope.example",
			ShareWith:       "pscope-user",
			Name:            "ct-pscope-share-A",
			ResourceType:    "file",
			Permissions:     []string{"read"},
			Status:          sharesinbox.ShareStatusPending,
			RecipientUserID: "ct-pscope-recipient-A",
			CreatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
			UpdatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
		}
		shareB := &sharesinbox.IncomingShare{
			ShareID:         "ct-pscope-in-s-B",
			ProviderID:      "ct-pscope-p1",
			SenderHost:      "ct.sender-b.pscope.example",
			ShareWith:       "pscope-user",
			Name:            "ct-pscope-share-B",
			ResourceType:    "file",
			Permissions:     []string{"read"},
			Status:          sharesinbox.ShareStatusPending,
			RecipientUserID: "ct-pscope-recipient-B",
			CreatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
			UpdatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
		}
		if err := r.IncomingShares.Create(ctx, shareA); err != nil {
			t.Fatalf("Create shareA: %v", err)
		}
		if err := r.IncomingShares.Create(ctx, shareB); err != nil {
			t.Fatalf("Create shareB: %v", err)
		}

		gotA, err := r.IncomingShares.GetByProviderID(ctx, shareA.SenderHost, "ct-pscope-p1")
		if err != nil {
			t.Fatalf("GetByProviderID senderHost-A: %v", err)
		}
		if gotA.ShareID != shareA.ShareID {
			t.Errorf("GetByProviderID senderHost-A: got ShareID %q, want %q", gotA.ShareID, shareA.ShareID)
		}

		gotB, err := r.IncomingShares.GetByProviderID(ctx, shareB.SenderHost, "ct-pscope-p1")
		if err != nil {
			t.Fatalf("GetByProviderID senderHost-B: %v", err)
		}
		if gotB.ShareID != shareB.ShareID {
			t.Errorf("GetByProviderID senderHost-B: got ShareID %q, want %q", gotB.ShareID, shareB.ShareID)
		}
	})

	t.Run("AutoFill", func(t *testing.T) {
		share := &sharesinbox.IncomingShare{
			ProviderID:      "ct-autofill-in-p1",
			SenderHost:      "ct.autofill.sender.example",
			ShareWith:       "autofill-user",
			Name:            "ct-autofill-inshare",
			Permissions:     []string{"read"},
			RecipientUserID: "ct-autofill-recipient",
		}
		if err := r.IncomingShares.Create(ctx, share); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if share.ShareID == "" {
			t.Error("ShareID not auto-filled after Create")
		}
		if share.CreatedAt.IsZero() {
			t.Error("CreatedAt not auto-filled after Create")
		}
		if share.UpdatedAt.IsZero() {
			t.Error("UpdatedAt not auto-filled after Create")
		}
	})

	t.Run("ErrShareNotFoundSentinel", func(t *testing.T) {
		_, err := r.IncomingShares.GetByIDForRecipientUserID(ctx, "ct-in-missing-share", "any-user")
		if !errors.Is(err, sharesinbox.ErrShareNotFound) {
			t.Errorf("expected ErrShareNotFound, got %v", err)
		}
	})
}
