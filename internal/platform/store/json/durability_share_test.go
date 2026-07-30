package json_test

import (
	"context"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

// TestJSONShareSaveFailureRollback verifies that when saveFile fails the
// in-memory share state is not left in a mutated state (no split-brain).
// The failure is injected by making the data directory read-only after Init,
// mirroring the pattern used by TestJSONInviteSaveFailureRollback.
func TestJSONShareSaveFailureRollback(t *testing.T) { //nolint:dupl // intentional: parallel invite/share rollback suites share table-driven structure but cover different entity types
	if os.Getuid() == 0 {
		t.Skip("cannot test read-only dir as root")
	}

	ctx := context.Background()

	t.Run("CreateOutgoingShare", func(t *testing.T) { testCreateOutgoingShareRollback(t, ctx) })
	t.Run("UpdateOutgoingShare", func(t *testing.T) { testUpdateOutgoingShareRollback(t, ctx) })
	t.Run("DeleteOutgoingShare", func(t *testing.T) { testDeleteOutgoingShareRollback(t, ctx) })
	t.Run("CreateIncomingShare", func(t *testing.T) { testCreateIncomingShareRollback(t, ctx) })
	t.Run("UpdateIncomingShareStatusForRecipient", func(t *testing.T) { testUpdateIncomingShareStatusRollback(t, ctx) })
	t.Run("DeleteIncomingShareForRecipient", func(t *testing.T) { testDeleteIncomingShareRollback(t, ctx) })
}

func makeShareDriver(t *testing.T, dir string) store.Driver {
	t.Helper()

	cfg := &store.DriverConfig{Driver: "json", DataDir: dir}

	return testutil.OpenDriver(t, cfg)
}

func lockShareDir(t *testing.T, dir string) {
	t.Helper()

	if err := os.Chmod(dir, 0500); err != nil { //nolint:gosec // test temp dir: restrictive 0500 mode is intentional for test isolation
		t.Fatal(err)
	}

	t.Cleanup(func() {
		os.Chmod(dir, 0700) //nolint:errcheck,gosec // test cleanup: restore directory permissions; test temp dir: restrictive 0700 mode is intentional for test isolation
	})
}

func testCreateOutgoingShareRollback(t *testing.T, ctx context.Context) {
	t.Helper()

	dir := testutil.TempDataDir(t, "ocm-test-json-rollback-create-out-share-*")

	d := makeShareDriver(t, dir) //nolint:contextcheck // test: no context propagation needed
	defer d.Close()              //nolint:errcheck // test cleanup: driver close

	outStore := requireOutgoingShareStore(t, d)

	share := testutil.NewOutgoingShareFixture()

	lockShareDir(t, dir)

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

	d := makeShareDriver(t, dir) //nolint:contextcheck // test: no context propagation needed
	defer d.Close()              //nolint:errcheck // test cleanup: driver close

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

	lockShareDir(t, dir)

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

	d := makeShareDriver(t, dir) //nolint:contextcheck // test: no context propagation needed
	defer d.Close()              //nolint:errcheck // test cleanup: driver close

	outStore := requireOutgoingShareStore(t, d)

	share := testutil.NewOutgoingShareFixture()
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("setup CreateOutgoingShare: %v", err)
	}

	lockShareDir(t, dir)

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

	d := makeShareDriver(t, dir) //nolint:contextcheck // test: no context propagation needed
	defer d.Close()              //nolint:errcheck // test cleanup: driver close

	inStore := requireIncomingShareStore(t, d)

	share := testutil.NewIncomingShareFixture()

	lockShareDir(t, dir)

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

	d := makeShareDriver(t, dir) //nolint:contextcheck // test: no context propagation needed
	defer d.Close()              //nolint:errcheck // test cleanup: driver close

	inStore := requireIncomingShareStore(t, d)

	share := testutil.NewIncomingShareFixture()
	if err := inStore.CreateIncomingShare(ctx, share); err != nil {
		t.Fatalf("setup CreateIncomingShare: %v", err)
	}

	oldStatus := share.Status
	oldUpdatedAt := share.UpdatedAt

	lockShareDir(t, dir)

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

	d := makeShareDriver(t, dir) //nolint:contextcheck // test: no context propagation needed
	defer d.Close()              //nolint:errcheck // test cleanup: driver close

	inStore := requireIncomingShareStore(t, d)

	share := testutil.NewIncomingShareFixture()
	if err := inStore.CreateIncomingShare(ctx, share); err != nil {
		t.Fatalf("setup CreateIncomingShare: %v", err)
	}

	lockShareDir(t, dir)

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
