// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package json_test

import (
	"context"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

// TestJSONShareSaveFailureRollback verifies that when saveFile fails the
// in-memory share state is not left in a mutated state (no split-brain).
// The failure is injected by making the data directory read-only after Init,
// mirroring the pattern used by TestJSONInviteSaveFailureRollback.
func TestJSONShareSaveFailureRollback(t *testing.T) {
	runRollbackSuite(t, []rollbackCase{
		{"CreateOutgoingShare", testCreateOutgoingShareRollback},
		{"UpdateOutgoingShare", testUpdateOutgoingShareRollback},
		{"DeleteOutgoingShare", testDeleteOutgoingShareRollback},
		{"CreateIncomingShare", testCreateIncomingShareRollback},
		{"UpdateIncomingShareStatusForRecipient", testUpdateIncomingShareStatusRollback},
		{"DeleteIncomingShareForRecipient", testDeleteIncomingShareRollback},
	})
}

func testCreateOutgoingShareRollback(t *testing.T, ctx context.Context) {
	t.Helper()

	dir := testutil.TempDataDir(t, "ocm-test-json-rollback-create-out-share-*")

	d := makeDriver(t, dir) //nolint:contextcheck // test helper: driver open accepts no context
	defer tshttp.MustClose(t, d)

	outStore := requireOutgoingShareStore(t, d)

	share := testutil.NewOutgoingShareFixture()

	lockDir(t, dir)

	if err := outStore.CreateOutgoingShare(ctx, share); err == nil {
		t.Fatal("expected error from CreateOutgoingShare with read-only dir, got nil")
	}

	// Restore write permission and verify primary record and all secondary
	// indexes are absent (rollback succeeded).
	restoreDirPerms(t, dir)

	if _, err := outStore.GetOutgoingShare(ctx, share.ProviderID); err == nil {
		t.Error("share found in memory after failed create - rollback did not occur")
	}

	if _, err := outStore.GetOutgoingShareByID(ctx, share.ShareID); err == nil {
		t.Error("shareID index not rolled back after failed create")
	}

	if _, err := outStore.GetOutgoingShareByWebDAVID(ctx, share.WebDAVID); err == nil {
		t.Error("webdavID index not rolled back after failed create")
	}

	if _, err := outStore.GetOutgoingShareBySharedSecret(ctx, share.SharedSecret); err == nil {
		t.Error("sharedSecret index not rolled back after failed create")
	}
}

func testUpdateOutgoingShareRollback(t *testing.T, ctx context.Context) {
	t.Helper()

	dir := testutil.TempDataDir(t, "ocm-test-json-rollback-update-out-share-*")

	d := makeDriver(t, dir) //nolint:contextcheck // test helper: driver open accepts no context
	defer tshttp.MustClose(t, d)

	outStore := requireOutgoingShareStore(t, d)

	share := testutil.NewOutgoingShareFixture()
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("setup CreateOutgoingShare: %v", err)
	}

	// Use distinct new values for all three index fields so we can verify
	// neither the primary record nor any index entry was swapped.
	updated := *share
	updated.ShareID = "new-share-id"
	updated.WebDAVID = "new-webdav-id"
	updated.SharedSecret = "new-secret"
	updated.Status = "accepted"

	lockDir(t, dir)

	if err := outStore.UpdateOutgoingShare(ctx, &updated); err == nil {
		t.Fatal("expected error from UpdateOutgoingShare with read-only dir, got nil")
	}

	// Restore and verify the old record and all old indexes are intact.
	restoreDirPerms(t, dir)

	got, err := outStore.GetOutgoingShare(ctx, share.ProviderID)
	if err != nil {
		t.Fatalf("share missing after failed update: %v", err)
	}

	if got.Status != share.Status {
		t.Errorf(
			"in-memory state changed after failed update: got %q, want %q",
			got.Status,
			share.Status,
		)
	}

	if got.ShareID != share.ShareID {
		t.Errorf(
			"in-memory shareID changed after failed update: got %q, want %q",
			got.ShareID,
			share.ShareID,
		)
	}
	// Old indexes must still resolve.
	if _, err := outStore.GetOutgoingShareByID(ctx, share.ShareID); err != nil {
		t.Error("old shareID index entry missing after failed update rollback")
	}

	if _, err := outStore.GetOutgoingShareByWebDAVID(ctx, share.WebDAVID); err != nil {
		t.Error("old webdavID index entry missing after failed update rollback")
	}

	if _, err := outStore.GetOutgoingShareBySharedSecret(ctx, share.SharedSecret); err != nil {
		t.Error("old sharedSecret index entry missing after failed update rollback")
	}
	// New indexes must NOT resolve.
	if _, err := outStore.GetOutgoingShareByID(ctx, updated.ShareID); err == nil {
		t.Error("new shareID index entry present after failed update - rollback incomplete")
	}

	if _, err := outStore.GetOutgoingShareByWebDAVID(ctx, updated.WebDAVID); err == nil {
		t.Error("new webdavID index entry present after failed update - rollback incomplete")
	}

	if _, err := outStore.GetOutgoingShareBySharedSecret(ctx, updated.SharedSecret); err == nil {
		t.Error("new sharedSecret index entry present after failed update - rollback incomplete")
	}
}

func testDeleteOutgoingShareRollback(t *testing.T, ctx context.Context) {
	t.Helper()

	dir := testutil.TempDataDir(t, "ocm-test-json-rollback-delete-out-share-*")

	d := makeDriver(t, dir) //nolint:contextcheck // test helper: driver open accepts no context
	defer tshttp.MustClose(t, d)

	outStore := requireOutgoingShareStore(t, d)

	share := testutil.NewOutgoingShareFixture()
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("setup CreateOutgoingShare: %v", err)
	}

	lockDir(t, dir)

	if err := outStore.DeleteOutgoingShare(ctx, share.ProviderID); err == nil {
		t.Fatal("expected error from DeleteOutgoingShare with read-only dir, got nil")
	}

	// Restore and verify the share and all indexes are still present.
	restoreDirPerms(t, dir)

	if _, err := outStore.GetOutgoingShare(ctx, share.ProviderID); err != nil {
		t.Errorf("share missing after failed delete - rollback did not occur: %v", err)
	}

	if _, err := outStore.GetOutgoingShareByID(ctx, share.ShareID); err != nil {
		t.Error("shareID index entry missing after failed delete rollback")
	}

	if _, err := outStore.GetOutgoingShareByWebDAVID(ctx, share.WebDAVID); err != nil {
		t.Error("webdavID index entry missing after failed delete rollback")
	}

	if _, err := outStore.GetOutgoingShareBySharedSecret(ctx, share.SharedSecret); err != nil {
		t.Error("sharedSecret index entry missing after failed delete rollback")
	}
}

func testCreateIncomingShareRollback(t *testing.T, ctx context.Context) {
	t.Helper()

	dir := testutil.TempDataDir(t, "ocm-test-json-rollback-create-in-share-*")

	d := makeDriver(t, dir) //nolint:contextcheck // test helper: driver open accepts no context
	defer tshttp.MustClose(t, d)

	inStore := requireIncomingShareStore(t, d)

	share := testutil.NewIncomingShareFixture()

	lockDir(t, dir)

	if err := inStore.CreateIncomingShare(ctx, share); err == nil {
		t.Fatal("expected error from CreateIncomingShare with read-only dir, got nil")
	}

	restoreDirPerms(t, dir)

	if _, err := inStore.GetIncomingShareByIDForRecipient(
		ctx, share.ShareID, share.RecipientUserID,
	); err == nil {
		t.Error("incoming share found in memory after failed create - rollback did not occur")
	}

	if _, err := inStore.GetIncomingShareByProviderKey(
		ctx, share.SenderHost, share.ProviderID,
	); err == nil {
		t.Error("provider-key index not rolled back after failed create")
	}
}

func testUpdateIncomingShareStatusRollback(t *testing.T, ctx context.Context) {
	t.Helper()

	dir := testutil.TempDataDir(t, "ocm-test-json-rollback-update-in-share-*")

	d := makeDriver(t, dir) //nolint:contextcheck // test helper: driver open accepts no context
	defer tshttp.MustClose(t, d)

	inStore := requireIncomingShareStore(t, d)

	share := testutil.NewIncomingShareFixture()
	if err := inStore.CreateIncomingShare(ctx, share); err != nil {
		t.Fatalf("setup CreateIncomingShare: %v", err)
	}

	oldStatus := share.Status
	oldUpdatedAt := share.UpdatedAt

	lockDir(t, dir)

	if err := inStore.UpdateIncomingShareStatusForRecipient(
		ctx, share.ShareID, share.RecipientUserID, "accepted",
	); err == nil {
		t.Fatal("expected error from UpdateIncomingShareStatusForRecipient with read-only dir, got nil")
	}

	// Restore and verify both State and UpdatedAt reverted (rollback succeeded).
	restoreDirPerms(t, dir)

	got, err := inStore.GetIncomingShareByIDForRecipient(
		ctx, share.ShareID, share.RecipientUserID,
	)
	if err != nil {
		t.Fatalf("share missing after failed status update: %v", err)
	}

	if got.Status != oldStatus {
		t.Errorf(
			"in-memory state changed after failed update: got %q, want %q",
			got.Status,
			oldStatus,
		)
	}

	if got.UpdatedAt != oldUpdatedAt {
		t.Errorf(
			"in-memory UpdatedAt changed after failed update: got %d, want %d",
			got.UpdatedAt,
			oldUpdatedAt,
		)
	}
}

func testDeleteIncomingShareRollback(t *testing.T, ctx context.Context) { //nolint:dupl // intentional: parallel invite/share delete rollback helpers share read-only-dir pattern but cover different stores
	t.Helper()

	dir := testutil.TempDataDir(t, "ocm-test-json-rollback-delete-in-share-*")

	d := makeDriver(t, dir) //nolint:contextcheck // test helper: driver open accepts no context
	defer tshttp.MustClose(t, d)

	inStore := requireIncomingShareStore(t, d)

	share := testutil.NewIncomingShareFixture()
	if err := inStore.CreateIncomingShare(ctx, share); err != nil {
		t.Fatalf("setup CreateIncomingShare: %v", err)
	}

	lockDir(t, dir)

	if err := inStore.DeleteIncomingShareForRecipient(
		ctx, share.ShareID, share.RecipientUserID,
	); err == nil {
		t.Fatal("expected error from DeleteIncomingShareForRecipient with read-only dir, got nil")
	}

	// Restore and verify the share and provider-key index are still present.
	restoreDirPerms(t, dir)

	if _, err := inStore.GetIncomingShareByIDForRecipient(
		ctx, share.ShareID, share.RecipientUserID,
	); err != nil {
		t.Errorf("share missing after failed delete - rollback did not occur: %v", err)
	}

	if _, err := inStore.GetIncomingShareByProviderKey(
		ctx, share.SenderHost, share.ProviderID,
	); err != nil {
		t.Error("provider-key index entry missing after failed delete rollback")
	}
}
