// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package json_test

import (
	"context"
	"encoding/json"
	"errors"
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
// (WebDAVID, ShareID, SharedSecret) change. GetOutgoingShare returns a clone,
// so the mutated local copy does not affect the stored record before Update is
// called; the driver must still derive and remove all old keys.
func TestJSONOutgoingShareUpdateRefreshesIndexes(t *testing.T) {
	driver := newJSONDriver(t)
	defer driver.Close() //nolint:errcheck // test cleanup: driver close

	ctx := context.Background()

	outStore := requireOutgoingShareStore(t, driver)

	share := testutil.NewOutgoingShareFixture()
	share.WebDAVID = "original-webdav"
	share.ShareID = "original-share-id"

	share.SharedSecret = "original-secret"
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("CreateOutgoingShare: %v", err)
	}

	// GetOutgoingShare returns a clone, not the internal pointer.
	retrieved, err := outStore.GetOutgoingShare(ctx, share.ProviderID)
	if err != nil {
		t.Fatalf("GetOutgoingShare: %v", err)
	}

	// Change all three indexed key fields on the clone before updating.
	retrieved.WebDAVID = "new-webdav"
	retrieved.ShareID = "new-share-id"
	retrieved.SharedSecret = "new-secret"

	if err := outStore.UpdateOutgoingShare(ctx, retrieved); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Fatalf("UpdateOutgoingShare: %v", err)
	}

	// Old index entries must be gone.
	if _, err := outStore.GetOutgoingShareByID(ctx, "original-share-id"); !errors.Is(err, store.ErrNotFound) { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Errorf("stale shareID index entry survives: expected ErrNotFound, got %v", err)
	}

	if _, err := outStore.GetOutgoingShareByWebDAVID(ctx, "original-webdav"); !errors.Is(err, store.ErrNotFound) { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Errorf("stale webdav index entry survives: expected ErrNotFound, got %v", err)
	}

	if _, err := outStore.GetOutgoingShareBySharedSecret(ctx, "original-secret"); !errors.Is(err, store.ErrNotFound) { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Errorf("stale secret index entry survives: expected ErrNotFound, got %v", err)
	}

	// New index entries must resolve correctly.
	got, err := outStore.GetOutgoingShareByWebDAVID(ctx, "new-webdav")
	if err != nil {
		t.Fatalf("GetOutgoingShareByWebDAVID(new-webdav): %v", err)
	}

	if got.ProviderID != share.ProviderID {
		t.Errorf("wrong share returned: expected %q, got %q", share.ProviderID, got.ProviderID)
	}

	got, err = outStore.GetOutgoingShareByID(ctx, "new-share-id")
	if err != nil {
		t.Fatalf("GetOutgoingShareByID(new-share-id): %v", err)
	}

	if got.ProviderID != share.ProviderID {
		t.Errorf(
			"wrong share returned via shareID: expected %q, got %q",
			share.ProviderID,
			got.ProviderID,
		)
	}

	got, err = outStore.GetOutgoingShareBySharedSecret(ctx, "new-secret")
	if err != nil {
		t.Fatalf("GetOutgoingShareBySharedSecret(new-secret): %v", err)
	}

	if got.ProviderID != share.ProviderID {
		t.Errorf("wrong share returned via secret: expected %q, got %q", share.ProviderID, got.ProviderID)
	}
}

// TestJSONRebuildRejectsDuplicateOutgoingShareWebDAVID verifies that Init
// fails when persisted outgoing-share data contains two records with the same
// WebDAVID.
func TestJSONRebuildRejectsDuplicateOutgoingShareWebDAVID(t *testing.T) { //nolint:dupl // intentional: parallel duplicate-key rebuild tests share corrupt-data setup but inject different conflicting fields
	tempDir, err := os.MkdirTemp("", "ocm-test-json-dup-webdav-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir) //nolint:errcheck // test cleanup: temp directory remove

	if err := os.MkdirAll(tempDir, 0700); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Fatal(err)
	}

	now := time.Now().Unix()
	shares := map[string]*store.OutgoingShare{
		"provider-a": {
			ProviderID: "provider-a",
			ShareID:    "share-a",
			WebDAVID:   "dup-webdav-id",
			CreatedAt:  now,
			UpdatedAt:  now,
		},
		"provider-b": {
			ProviderID: "provider-b",
			ShareID:    "share-b",
			WebDAVID:   "dup-webdav-id", // same WebDAVID - corrupt
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
	defer d.Close() //nolint:errcheck // test cleanup: driver close

	if err := d.Init(context.Background()); err == nil {
		t.Fatal("expected Init to fail for duplicate outgoing-share WebDAVID, but it succeeded")
	}
}

// TestJSONRebuildRejectsDuplicateOutgoingShareID verifies that Init fails when
// persisted outgoing-share data contains two records with the same ShareID.
func TestJSONRebuildRejectsDuplicateOutgoingShareID(t *testing.T) { //nolint:dupl // intentional: parallel duplicate-key rebuild tests share corrupt-data setup but inject different conflicting fields
	tempDir, err := os.MkdirTemp("", "ocm-test-json-dup-shareid-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir) //nolint:errcheck // test cleanup: temp directory remove

	if err := os.MkdirAll(tempDir, 0700); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Fatal(err)
	}

	now := time.Now().Unix()
	shares := map[string]*store.OutgoingShare{
		"provider-x": {
			ProviderID: "provider-x",
			ShareID:    "dup-share-id", // same ShareID - corrupt
			WebDAVID:   "webdav-x",
			CreatedAt:  now,
			UpdatedAt:  now,
		},
		"provider-y": {
			ProviderID: "provider-y",
			ShareID:    "dup-share-id", // same ShareID - corrupt
			WebDAVID:   "webdav-y",
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
	defer d.Close() //nolint:errcheck // test cleanup: driver close

	if err := d.Init(context.Background()); err == nil {
		t.Fatal("expected Init to fail for duplicate outgoing-share ShareID, but it succeeded")
	}
}

// TestJSONRebuildRejectsDuplicateOutgoingInviteToken verifies that Init fails
// when persisted outgoing-invite data contains two records with the same Token.
func TestJSONRebuildRejectsDuplicateOutgoingInviteToken(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-json-dup-inv-tok-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir) //nolint:errcheck // test cleanup: temp directory remove

	if err := os.MkdirAll(tempDir, 0700); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
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
	defer d.Close() //nolint:errcheck // test cleanup: driver close

	if err := d.Init(context.Background()); err == nil {
		t.Fatal("expected Init to fail for duplicate outgoing-invite Token, but it succeeded")
	}
}
