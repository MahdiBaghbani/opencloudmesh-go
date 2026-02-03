package shares_test

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// --- Repository ---

func TestIncomingRepository_SenderScopedStorage(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	ctx := context.Background()

	share1 := &shares.IncomingShare{
		ProviderID:      "same-id",
		SenderHost:      "sender1.example.com",
		ShareWith:       "user@example.com",
		RecipientUserID: "user-a",
		Status:          shares.ShareStatusPending,
	}
	if err := repo.Create(ctx, share1); err != nil {
		t.Fatalf("failed to create share1: %v", err)
	}

	share2 := &shares.IncomingShare{
		ProviderID:      "same-id",
		SenderHost:      "sender2.example.com",
		ShareWith:       "user@example.com",
		RecipientUserID: "user-a",
		Status:          shares.ShareStatusPending,
	}
	if err := repo.Create(ctx, share2); err != nil {
		t.Fatalf("failed to create share2: %v", err)
	}

	// Duplicate from sender1 should fail
	share3 := &shares.IncomingShare{
		ProviderID:      "same-id",
		SenderHost:      "sender1.example.com",
		ShareWith:       "user@example.com",
		RecipientUserID: "user-a",
		Status:          shares.ShareStatusPending,
	}
	if err := repo.Create(ctx, share3); err == nil {
		t.Error("expected error for duplicate providerId from same sender")
	}

	// Lookup by sender-scoped providerId
	found, err := repo.GetByProviderID(ctx, "sender1.example.com", "same-id")
	if err != nil {
		t.Fatalf("failed to find share: %v", err)
	}
	if found.ShareID != share1.ShareID {
		t.Error("wrong share returned for sender1")
	}
}

func TestIncomingRepository_RecipientScoping(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	ctx := context.Background()

	// Create shares for different recipients
	shareA := &shares.IncomingShare{
		ProviderID:      "p1",
		SenderHost:      "sender.com",
		RecipientUserID: "user-a",
		Status:          shares.ShareStatusPending,
	}
	repo.Create(ctx, shareA)

	shareB := &shares.IncomingShare{
		ProviderID:      "p2",
		SenderHost:      "sender.com",
		RecipientUserID: "user-b",
		Status:          shares.ShareStatusPending,
	}
	repo.Create(ctx, shareB)

	// User A should only see their share
	listA, _ := repo.ListByRecipientUserID(ctx, "user-a")
	if len(listA) != 1 {
		t.Fatalf("user-a: expected 1 share, got %d", len(listA))
	}
	if listA[0].ShareID != shareA.ShareID {
		t.Error("user-a: got wrong share")
	}

	// User B should only see their share
	listB, _ := repo.ListByRecipientUserID(ctx, "user-b")
	if len(listB) != 1 {
		t.Fatalf("user-b: expected 1 share, got %d", len(listB))
	}

	// User A cannot get user B's share
	_, err := repo.GetByIDForRecipientUserID(ctx, shareB.ShareID, "user-a")
	if err == nil {
		t.Error("expected error when user-a tries to access user-b's share")
	}

	// User A cannot update user B's share
	err = repo.UpdateStatusForRecipientUserID(ctx, shareB.ShareID, "user-a", shares.ShareStatusAccepted)
	if err == nil {
		t.Error("expected error when user-a tries to update user-b's share")
	}

	// User A cannot delete user B's share
	err = repo.DeleteForRecipientUserID(ctx, shareB.ShareID, "user-a")
	if err == nil {
		t.Error("expected error when user-a tries to delete user-b's share")
	}
}

func TestWebDAVProtocol_HasRequirement(t *testing.T) {
	p := &spec.WebDAVProtocol{
		URI:          "abc123",
		Permissions:  []string{"read"},
		Requirements: []string{"must-exchange-token"},
	}

	if !p.HasRequirement("must-exchange-token") {
		t.Error("expected true for must-exchange-token")
	}
	if p.HasRequirement("must-use-mfa") {
		t.Error("expected false for must-use-mfa")
	}
}
