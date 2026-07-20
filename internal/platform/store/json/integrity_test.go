package json_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

// writePersistedJSON writes data directly to a named JSON file in dir,
// bypassing the driver's normal write path. Used to inject corrupt state.
func writePersistedJSON(t *testing.T, dir, filename string, data interface{}) {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("writePersistedJSON marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, filename), raw, 0600); err != nil {
		t.Fatalf("writePersistedJSON write %s: %v", filename, err)
	}
}

// TestJSONOutgoingShareUpdateRefreshesIndexes verifies that UpdateOutgoingShare
// clears stale index entries and registers new ones when key fields
// (WebDAVId, ShareId, SharedSecret) change. GetOutgoingShare returns a clone,
// so the mutated local copy does not affect the stored record before Update is
// called; the driver must still derive and remove all old keys.
func TestJSONOutgoingShareUpdateRefreshesIndexes(t *testing.T) {
	driver, _ := newJSONDriver(t)
	defer driver.Close()
	ctx := context.Background()

	outStore := driver.(store.OutgoingShareStore)

	share := testutil.NewOutgoingShareFixture()
	share.WebDAVId = "original-webdav"
	share.ShareId = "original-share-id"
	share.SharedSecret = "original-secret"
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("CreateOutgoingShare: %v", err)
	}

	// GetOutgoingShare returns a clone, not the internal pointer.
	retrieved, err := outStore.GetOutgoingShare(ctx, share.ProviderId)
	if err != nil {
		t.Fatalf("GetOutgoingShare: %v", err)
	}

	// Change all three indexed key fields on the clone before updating.
	retrieved.WebDAVId = "new-webdav"
	retrieved.ShareId = "new-share-id"
	retrieved.SharedSecret = "new-secret"

	if err := outStore.UpdateOutgoingShare(ctx, retrieved); err != nil {
		t.Fatalf("UpdateOutgoingShare: %v", err)
	}

	// Old index entries must be gone.
	if _, err := outStore.GetOutgoingShareByID(ctx, "original-share-id"); err != store.ErrNotFound {
		t.Errorf("stale shareId index entry survives: expected ErrNotFound, got %v", err)
	}
	if _, err := outStore.GetOutgoingShareByWebDAVId(ctx, "original-webdav"); err != store.ErrNotFound {
		t.Errorf("stale webdav index entry survives: expected ErrNotFound, got %v", err)
	}
	if _, err := outStore.GetOutgoingShareBySharedSecret(ctx, "original-secret"); err != store.ErrNotFound {
		t.Errorf("stale secret index entry survives: expected ErrNotFound, got %v", err)
	}

	// New index entries must resolve correctly.
	got, err := outStore.GetOutgoingShareByWebDAVId(ctx, "new-webdav")
	if err != nil {
		t.Fatalf("GetOutgoingShareByWebDAVId(new-webdav): %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("wrong share returned: expected %q, got %q", share.ProviderId, got.ProviderId)
	}

	got, err = outStore.GetOutgoingShareByID(ctx, "new-share-id")
	if err != nil {
		t.Fatalf("GetOutgoingShareByID(new-share-id): %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf(
			"wrong share returned via shareId: expected %q, got %q",
			share.ProviderId,
			got.ProviderId,
		)
	}

	got, err = outStore.GetOutgoingShareBySharedSecret(ctx, "new-secret")
	if err != nil {
		t.Fatalf("GetOutgoingShareBySharedSecret(new-secret): %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("wrong share returned via secret: expected %q, got %q", share.ProviderId, got.ProviderId)
	}
}

// TestJSONRebuildRejectsDuplicateOutgoingShareWebDAVId verifies that Init
// fails when persisted outgoing-share data contains two records with the same
// WebDAVId.
func TestJSONRebuildRejectsDuplicateOutgoingShareWebDAVId(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-json-dup-webdav-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	if err := os.MkdirAll(tempDir, 0700); err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	shares := map[string]*store.OutgoingShare{
		"provider-a": {
			ProviderId: "provider-a",
			ShareId:    "share-a",
			WebDAVId:   "dup-webdav-id",
			CreatedAt:  now,
			UpdatedAt:  now,
		},
		"provider-b": {
			ProviderId: "provider-b",
			ShareId:    "share-b",
			WebDAVId:   "dup-webdav-id", // same WebDAVId - corrupt
			CreatedAt:  now,
			UpdatedAt:  now,
		},
	}
	writePersistedJSON(t, tempDir, "outgoing_shares.json", shares)

	cfg := &store.DriverConfig{Driver: "json", DataDir: tempDir}
	d, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	if err := d.Init(context.Background()); err == nil {
		t.Fatal("expected Init to fail for duplicate outgoing-share WebDAVId, but it succeeded")
	}
}

// TestJSONRebuildRejectsDuplicateOutgoingShareId verifies that Init fails when
// persisted outgoing-share data contains two records with the same ShareId.
func TestJSONRebuildRejectsDuplicateOutgoingShareId(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-json-dup-shareid-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	if err := os.MkdirAll(tempDir, 0700); err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	shares := map[string]*store.OutgoingShare{
		"provider-x": {
			ProviderId: "provider-x",
			ShareId:    "dup-share-id", // same ShareId - corrupt
			WebDAVId:   "webdav-x",
			CreatedAt:  now,
			UpdatedAt:  now,
		},
		"provider-y": {
			ProviderId: "provider-y",
			ShareId:    "dup-share-id", // same ShareId - corrupt
			WebDAVId:   "webdav-y",
			CreatedAt:  now,
			UpdatedAt:  now,
		},
	}
	writePersistedJSON(t, tempDir, "outgoing_shares.json", shares)

	cfg := &store.DriverConfig{Driver: "json", DataDir: tempDir}
	d, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	if err := d.Init(context.Background()); err == nil {
		t.Fatal("expected Init to fail for duplicate outgoing-share ShareId, but it succeeded")
	}
}

// TestJSONRebuildRejectsDuplicateOutgoingInviteToken verifies that Init fails
// when persisted outgoing-invite data contains two records with the same Token.
func TestJSONRebuildRejectsDuplicateOutgoingInviteToken(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-json-dup-inv-tok-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	if err := os.MkdirAll(tempDir, 0700); err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	invites := map[string]*store.OutgoingInvite{
		"invite-1": {
			ID:        "invite-1",
			Token:     "dup-token", // same Token - corrupt
			CreatedAt: now,
			UpdatedAt: now,
		},
		"invite-2": {
			ID:        "invite-2",
			Token:     "dup-token", // same Token - corrupt
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
	writePersistedJSON(t, tempDir, "outgoing_invites.json", invites)

	cfg := &store.DriverConfig{Driver: "json", DataDir: tempDir}
	d, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	if err := d.Init(context.Background()); err == nil {
		t.Fatal("expected Init to fail for duplicate outgoing-invite Token, but it succeeded")
	}
}
