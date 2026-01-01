// Package testutil provides shared test helpers for store driver tests.
package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/store"
)

// TestOutgoingShare creates a test outgoing share.
func TestOutgoingShare() *store.OutgoingShare {
	return &store.OutgoingShare{
		ProviderId:   "test-provider-id",
		WebDAVId:     "test-webdav-id",
		SharedSecret: "super-secret-token",
		LocalPath:    "/path/to/file.txt",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		State:        "pending",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
}

// TestIncomingShare creates a test incoming share.
func TestIncomingShare() *store.IncomingShare {
	return &store.IncomingShare{
		ShareId:       "test-share-id",
		SendingServer: "sender.com",
		ProviderId:    "remote-provider-id",
		WebDAVId:      "remote-webdav-id",
		SharedSecret:  "received-secret",
		Owner:         "alice@sender.com",
		Sender:        "alice@sender.com",
		ShareWith:     "bob@example.com",
		Name:          "shared-file.txt",
		ResourceType:  "file",
		Permissions:   "read",
		State:         "pending",
		UserId:        "bob",
		CreatedAt:     time.Now().Unix(),
		UpdatedAt:     time.Now().Unix(),
	}
}

// RunDriverTests runs the standard test suite against a driver.
func RunDriverTests(t *testing.T, driverName string, cfg *store.DriverConfig) {
	ctx := context.Background()

	driver, err := store.New(cfg)
	if err != nil {
		t.Fatalf("failed to create %s driver: %v", driverName, err)
	}
	defer driver.Close()

	if err := driver.Init(ctx); err != nil {
		t.Fatalf("failed to init %s driver: %v", driverName, err)
	}

	if driver.Name() != driverName {
		t.Errorf("expected driver name %q, got %q", driverName, driver.Name())
	}

	shareStore, ok := driver.(store.ShareStore)
	if !ok {
		t.Fatalf("%s driver does not implement ShareStore", driverName)
	}

	t.Run("OutgoingShareCRUD", func(t *testing.T) {
		TestOutgoingShareCRUD(t, ctx, shareStore)
	})

	t.Run("IncomingShareCRUD", func(t *testing.T) {
		TestIncomingShareCRUD(t, ctx, shareStore)
	})

	t.Run("ProviderKeyScopedLookup", func(t *testing.T) {
		TestProviderKeyScopedLookup(t, ctx, shareStore)
	})
}

// TestOutgoingShareCRUD tests CRUD operations for outgoing shares.
func TestOutgoingShareCRUD(t *testing.T, ctx context.Context, s store.ShareStore) {
	share := TestOutgoingShare()

	// Create
	if err := s.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("CreateOutgoingShare failed: %v", err)
	}

	// Get by providerId
	got, err := s.GetOutgoingShare(ctx, share.ProviderId)
	if err != nil {
		t.Fatalf("GetOutgoingShare failed: %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("expected providerId %q, got %q", share.ProviderId, got.ProviderId)
	}

	// Get by webdavId
	got, err = s.GetOutgoingShareByWebDAVId(ctx, share.WebDAVId)
	if err != nil {
		t.Fatalf("GetOutgoingShareByWebDAVId failed: %v", err)
	}
	if got.WebDAVId != share.WebDAVId {
		t.Errorf("expected webdavId %q, got %q", share.WebDAVId, got.WebDAVId)
	}

	// Update
	share.State = "accepted"
	if err := s.UpdateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("UpdateOutgoingShare failed: %v", err)
	}
	got, _ = s.GetOutgoingShare(ctx, share.ProviderId)
	if got.State != "accepted" {
		t.Errorf("expected state 'accepted', got %q", got.State)
	}

	// List
	shares, err := s.ListOutgoingShares(ctx)
	if err != nil {
		t.Fatalf("ListOutgoingShares failed: %v", err)
	}
	if len(shares) == 0 {
		t.Error("expected at least one share in list")
	}

	// Delete
	if err := s.DeleteOutgoingShare(ctx, share.ProviderId); err != nil {
		t.Fatalf("DeleteOutgoingShare failed: %v", err)
	}

	// Verify deleted
	_, err = s.GetOutgoingShare(ctx, share.ProviderId)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// TestIncomingShareCRUD tests CRUD operations for incoming shares.
func TestIncomingShareCRUD(t *testing.T, ctx context.Context, s store.ShareStore) {
	share := TestIncomingShare()

	// Create
	if err := s.CreateIncomingShare(ctx, share); err != nil {
		t.Fatalf("CreateIncomingShare failed: %v", err)
	}

	// Get by shareId
	got, err := s.GetIncomingShare(ctx, share.ShareId)
	if err != nil {
		t.Fatalf("GetIncomingShare failed: %v", err)
	}
	if got.ShareId != share.ShareId {
		t.Errorf("expected shareId %q, got %q", share.ShareId, got.ShareId)
	}

	// Get by provider key (sender-scoped)
	got, err = s.GetIncomingShareByProviderKey(ctx, share.SendingServer, share.ProviderId)
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey failed: %v", err)
	}
	if got.ShareId != share.ShareId {
		t.Errorf("expected shareId %q, got %q", share.ShareId, got.ShareId)
	}

	// Update
	share.State = "accepted"
	if err := s.UpdateIncomingShare(ctx, share); err != nil {
		t.Fatalf("UpdateIncomingShare failed: %v", err)
	}

	// List by user
	shares, err := s.ListIncomingShares(ctx, share.UserId)
	if err != nil {
		t.Fatalf("ListIncomingShares failed: %v", err)
	}
	if len(shares) == 0 {
		t.Error("expected at least one share in list")
	}

	// Delete
	if err := s.DeleteIncomingShare(ctx, share.ShareId); err != nil {
		t.Fatalf("DeleteIncomingShare failed: %v", err)
	}
}

// TestProviderKeyScopedLookup verifies sender-scoped provider key lookup.
func TestProviderKeyScopedLookup(t *testing.T, ctx context.Context, s store.ShareStore) {
	// Create two shares with same providerId but different senders
	share1 := TestIncomingShare()
	share1.ShareId = "share-1"
	share1.SendingServer = "server1.com"
	share1.ProviderId = "same-provider-id"

	share2 := TestIncomingShare()
	share2.ShareId = "share-2"
	share2.SendingServer = "server2.com"
	share2.ProviderId = "same-provider-id"

	if err := s.CreateIncomingShare(ctx, share1); err != nil {
		t.Fatalf("CreateIncomingShare share1 failed: %v", err)
	}
	if err := s.CreateIncomingShare(ctx, share2); err != nil {
		t.Fatalf("CreateIncomingShare share2 failed: %v", err)
	}

	// Lookup by server1 should return share1
	got, err := s.GetIncomingShareByProviderKey(ctx, "server1.com", "same-provider-id")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey server1 failed: %v", err)
	}
	if got.ShareId != "share-1" {
		t.Errorf("expected share-1, got %q", got.ShareId)
	}

	// Lookup by server2 should return share2
	got, err = s.GetIncomingShareByProviderKey(ctx, "server2.com", "same-provider-id")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey server2 failed: %v", err)
	}
	if got.ShareId != "share-2" {
		t.Errorf("expected share-2, got %q", got.ShareId)
	}

	// Cleanup
	s.DeleteIncomingShare(ctx, share1.ShareId)
	s.DeleteIncomingShare(ctx, share2.ShareId)
}
