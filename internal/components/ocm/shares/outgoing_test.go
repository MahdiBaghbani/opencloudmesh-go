package shares_test

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
)

func TestOutgoingShareRepo_CreateAndLookup(t *testing.T) {
	repo := shares.NewMemoryOutgoingShareRepo()
	ctx := context.Background()

	share := &shares.OutgoingShare{
		ProviderID:   "provider-123",
		WebDAVID:     "webdav-456",
		SharedSecret: "secret",
		LocalPath:    "/tmp/test.txt",
		ReceiverHost: "receiver.example.com",
		ShareWith:    "user@receiver.example.com",
		Name:         "test.txt",
		ResourceType: "file",
		ShareType:    "user",
		Permissions:  []string{"read"},
		Status:       "pending",
	}

	if err := repo.Create(ctx, share); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Lookup by shareID
	found, err := repo.GetByID(ctx, share.ShareID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if found.ProviderID != share.ProviderID {
		t.Error("wrong providerId")
	}

	// Lookup by providerId
	found, err = repo.GetByProviderID(ctx, "provider-123")
	if err != nil {
		t.Fatalf("GetByProviderID failed: %v", err)
	}
	if found.ShareID != share.ShareID {
		t.Error("wrong shareId from providerId lookup")
	}

	// Lookup by webdavId
	found, err = repo.GetByWebDAVID(ctx, "webdav-456")
	if err != nil {
		t.Fatalf("GetByWebDAVID failed: %v", err)
	}
	if found.ShareID != share.ShareID {
		t.Error("wrong shareId from webdavId lookup")
	}
}

// OutgoingHandler tests have been moved to internal/components/api/outgoing/shares/handler_test.go
