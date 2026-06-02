package repos_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

// TestRepoContract runs the full repo-level contract against every backend.
// memory is the semantic reference: all durable backends (json, sqlite, mirror)
// must match its observable behavior on every operation including list
// operations and recipient-scoped access.
func TestRepoContract(t *testing.T) {
	backends := []struct {
		name string
		open func(*testing.T) *repos.Repos
	}{
		{"memory", newMemoryRepos},
		{"json", newJSONRepos},
		{
			"sqlite",
			func(t *testing.T) *repos.Repos {
				return newDurableRepos(t, config.BackendSQLite)
			},
		},
		{
			"mirror",
			func(t *testing.T) *repos.Repos {
				return newDurableRepos(t, config.BackendMirror)
			},
		},
	}
	for _, tt := range backends {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			r := tt.open(t)
			defer r.Close()
			runRepoContract(t, r)
		})
	}
}

// TestDurableDriverSurfaceParity is an explicit guard that json, sqlite, and
// mirror each expose all four app repo interfaces and that every required list
// operation is callable without error. repos.New returns an error if the
// underlying store driver does not implement the fullStore union (via
// type-assertion in newDurableRepos); this test makes that assertion visible
// and also smoke-tests each list operation to confirm it is wired correctly.
func TestDurableDriverSurfaceParity(t *testing.T) {
	ctx := context.Background()

	for _, backend := range []string{
		config.BackendJSON,
		config.BackendSQLite,
		config.BackendMirror,
	} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			// repos.New internally type-asserts drv.(fullStore); failure here
			// means the driver is missing at least one store interface.
			r := newDurableRepos(t, backend)
			defer r.Close()

			if r.OutgoingShares == nil {
				t.Fatalf("%s: OutgoingShares is nil", backend)
			}
			if r.IncomingShares == nil {
				t.Fatalf("%s: IncomingShares is nil", backend)
			}
			if r.OutgoingInvites == nil {
				t.Fatalf("%s: OutgoingInvites is nil", backend)
			}
			if r.IncomingInvites == nil {
				t.Fatalf("%s: IncomingInvites is nil", backend)
			}

			// Smoke-test every list operation against an empty store to confirm
			// the method is implemented and correctly wired.
			if _, err := r.OutgoingShares.List(ctx); err != nil {
				t.Errorf("OutgoingShares.List on empty store: %v", err)
			}
			if _, err := r.IncomingShares.ListByRecipientUserID(ctx, "parity-user"); err != nil {
				t.Errorf("IncomingShares.ListByRecipientUserID on empty store: %v", err)
			}
			if _, err := r.OutgoingInvites.List(ctx); err != nil {
				t.Errorf("OutgoingInvites.List on empty store: %v", err)
			}
			if _, err := r.IncomingInvites.ListByRecipientUserID(ctx, "parity-user"); err != nil {
				t.Errorf("IncomingInvites.ListByRecipientUserID on empty store: %v", err)
			}
		})
	}
}

// runRepoContract exercises all four app repo interfaces against a single
// *repos.Repos instance. All subtests use IDs that are unique within this
// call so no state leaks between subtests.
func runRepoContract(t *testing.T, r *repos.Repos) {
	t.Helper()
	t.Run("OutgoingShares", func(t *testing.T) {
		runOutgoingShareRepoContract(t, r)
	})
	t.Run("IncomingShares", func(t *testing.T) {
		runIncomingShareRepoContract(t, r)
	})
	t.Run("OutgoingInvites", func(t *testing.T) {
		runOutgoingInviteRepoContract(t, r)
	})
	t.Run("IncomingInvites", func(t *testing.T) {
		runIncomingInviteRepoContract(t, r)
	})
}

// runOutgoingShareRepoContract verifies CRUD, list, auto-fill, and not-found
// sentinel behaviour for the OutgoingShareRepo interface.
func runOutgoingShareRepoContract(t *testing.T, r *repos.Repos) {
	t.Helper()
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		share := &sharesoutgoing.OutgoingShare{
			ShareID:      "ct-out-s1",
			ProviderID:   "ct-out-p1",
			WebDAVID:     "ct-out-w1",
			SharedSecret: "ct-secret-1",
			ShareWith:    "alice@peer",
			Name:         "ct-outshare",
			ResourceType: "file",
			Permissions:  []string{"read"},
			Status:       "sent",
			CreatedAt:    time.Unix(time.Now().Unix(), 0).UTC(),
		}
		if err := r.OutgoingShares.Create(ctx, share); err != nil {
			t.Fatalf("Create: %v", err)
		}

		got, err := r.OutgoingShares.GetByID(ctx, share.ShareID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.ShareID != share.ShareID {
			t.Errorf("GetByID ShareID: got %q, want %q", got.ShareID, share.ShareID)
		}

		got, err = r.OutgoingShares.GetByProviderID(ctx, share.ProviderID)
		if err != nil {
			t.Fatalf("GetByProviderID: %v", err)
		}
		if got.ProviderID != share.ProviderID {
			t.Errorf("GetByProviderID: got %q, want %q", got.ProviderID, share.ProviderID)
		}

		got, err = r.OutgoingShares.GetByWebDAVID(ctx, share.WebDAVID)
		if err != nil {
			t.Fatalf("GetByWebDAVID: %v", err)
		}
		if got.WebDAVID != share.WebDAVID {
			t.Errorf("GetByWebDAVID: got %q, want %q", got.WebDAVID, share.WebDAVID)
		}

		got, err = r.OutgoingShares.GetBySharedSecret(ctx, share.SharedSecret)
		if err != nil {
			t.Fatalf("GetBySharedSecret: %v", err)
		}
		if got.SharedSecret != share.SharedSecret {
			t.Errorf("GetBySharedSecret: got %q, want %q", got.SharedSecret, share.SharedSecret)
		}

		share.Status = "accepted"
		if err := r.OutgoingShares.Update(ctx, share); err != nil {
			t.Fatalf("Update: %v", err)
		}
		got, err = r.OutgoingShares.GetByID(ctx, share.ShareID)
		if err != nil {
			t.Fatalf("GetByID after Update: %v", err)
		}
		if got.Status != "accepted" {
			t.Errorf("Status after Update: got %q, want accepted", got.Status)
		}
	})

	t.Run("List", func(t *testing.T) {
		share := &sharesoutgoing.OutgoingShare{
			ShareID:      "ct-list-out-s1",
			ProviderID:   "ct-list-out-p1",
			WebDAVID:     "ct-list-out-w1",
			SharedSecret: "ct-list-secret-1",
			ShareWith:    "bob@peer",
			Name:         "ct-list-share",
			ResourceType: "file",
			Permissions:  []string{"read"},
			Status:       "sent",
			CreatedAt:    time.Unix(time.Now().Unix(), 0).UTC(),
		}
		if err := r.OutgoingShares.Create(ctx, share); err != nil {
			t.Fatalf("Create: %v", err)
		}

		all, err := r.OutgoingShares.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		found := false
		for _, s := range all {
			if s.ShareID == share.ShareID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("List: created share %q not found in result", share.ShareID)
		}
	})

	t.Run("AutoFill", func(t *testing.T) {
		share := &sharesoutgoing.OutgoingShare{
			ProviderID:  "ct-autofill-out-p1",
			WebDAVID:    "ct-autofill-out-w1",
			ShareWith:   "carol@peer",
			Name:        "ct-autofill-share",
			Permissions: []string{"read"},
		}
		if err := r.OutgoingShares.Create(ctx, share); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if share.ShareID == "" {
			t.Error("ShareID not auto-filled after Create")
		}
		if share.CreatedAt.IsZero() {
			t.Error("CreatedAt not auto-filled after Create")
		}
	})

	t.Run("NotFoundSentinel", func(t *testing.T) {
		_, err := r.OutgoingShares.GetByID(ctx, "ct-out-missing-id")
		if err == nil {
			t.Error("GetByID nonexistent: expected error, got nil")
		}
		_, err = r.OutgoingShares.GetByProviderID(ctx, "ct-out-missing-provider")
		if err == nil {
			t.Error("GetByProviderID nonexistent: expected error, got nil")
		}
		_, err = r.OutgoingShares.GetBySharedSecret(ctx, "ct-out-missing-secret")
		if err == nil {
			t.Error("GetBySharedSecret nonexistent: expected error, got nil")
		}
	})
}

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

// runIncomingInviteRepoContract verifies CRUD, list, recipient-scope guard,
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

	t.Run("RecipientScopeGuard", func(t *testing.T) {
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
