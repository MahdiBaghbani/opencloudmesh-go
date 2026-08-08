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
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

// writePersistedJSON writes data directly to a named JSON file in dir,
// bypassing the driver's normal write path. Used to inject corrupt state.
func writePersistedJSON(t *testing.T, dir, filename string, data any) {
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
	t.Parallel()

	driver := newJSONDriver(t)
	defer tshttp.MustClose(t, driver)

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

	if serr := outStore.UpdateOutgoingShare(ctx, retrieved); serr != nil {
		t.Fatalf("UpdateOutgoingShare: %v", serr)
	}

	// Old index entries must be gone.
	if _, gerr := outStore.GetOutgoingShareByID(ctx, "original-share-id"); !errors.Is(gerr, store.ErrNotFound) {
		t.Errorf("stale shareID index entry survives: expected ErrNotFound, got %v", gerr)
	}

	if _, gerr := outStore.GetOutgoingShareByWebDAVID(ctx, "original-webdav"); !errors.Is(gerr, store.ErrNotFound) {
		t.Errorf("stale webdav index entry survives: expected ErrNotFound, got %v", gerr)
	}

	if _, gerr := outStore.GetOutgoingShareBySharedSecret(ctx, "original-secret"); !errors.Is(gerr, store.ErrNotFound) {
		t.Errorf("stale secret index entry survives: expected ErrNotFound, got %v", gerr)
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

// assertRebuildRejectsDuplicateOutgoingShares persists shares with an injected
// duplicate key and asserts driver Init fails during index rebuild. fieldLabel
// names the conflicting field in the failure message.
func assertRebuildRejectsDuplicateOutgoingShares(t *testing.T, shares map[string]*store.OutgoingShare, fieldLabel string) {
	t.Helper()

	tempDir := t.TempDir()

	if merr := os.MkdirAll(tempDir, 0700); merr != nil {
		t.Fatal(merr)
	}

	writePersistedJSON(t, tempDir, "outgoing_shares.json", shares)

	cfg := &store.DriverConfig{Driver: "json", DataDir: tempDir}

	d, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tshttp.MustClose(t, d)

	if err := d.Init(context.Background()); err == nil {
		t.Fatalf("expected Init to fail for duplicate outgoing-share %s, but it succeeded", fieldLabel)
	}
}

// TestJSONRebuildRejectsDuplicateOutgoingShareWebDAVID verifies that Init
// fails when persisted outgoing-share data contains two records with the same
// WebDAVID.
func TestJSONRebuildRejectsDuplicateOutgoingShareWebDAVID(t *testing.T) {
	t.Parallel()

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

	assertRebuildRejectsDuplicateOutgoingShares(t, shares, "WebDAVID")
}

// TestJSONRebuildRejectsDuplicateOutgoingShareID verifies that Init fails when
// persisted outgoing-share data contains two records with the same ShareID.
func TestJSONRebuildRejectsDuplicateOutgoingShareID(t *testing.T) {
	t.Parallel()

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

	assertRebuildRejectsDuplicateOutgoingShares(t, shares, "ShareID")
}

// TestJSONRebuildRejectsDuplicateOutgoingInviteToken verifies that Init fails
// when persisted outgoing-invite data contains two records with the same Token.
func TestJSONRebuildRejectsDuplicateOutgoingInviteToken(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()

	if merr := os.MkdirAll(tempDir, 0700); merr != nil {
		t.Fatal(merr)
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
	defer tshttp.MustClose(t, d)

	if err := d.Init(context.Background()); err == nil {
		t.Fatal("expected Init to fail for duplicate outgoing-invite Token, but it succeeded")
	}
}
