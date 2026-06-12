package repos_test

import (
	"context"
	"testing"
	"time"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

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
