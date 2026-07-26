package json_test

import (
	"context"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

// TestJSONInviteReopenDurability verifies that both invite surfaces persist
// and reload correctly after the JSON driver is closed and reopened.
func TestJSONShareSaveFailureRollback(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("cannot test read-only dir as root")
	}

	ctx := context.Background()

	makeDriver := func(t *testing.T, dir string) store.Driver {
		t.Helper()

		cfg := &store.DriverConfig{Driver: "json", DataDir: dir}

		return testutil.OpenDriver(t, cfg)
	}

	lockDir := func(t *testing.T, dir string) {
		t.Helper()

		if err := os.Chmod(dir, 0500); err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { os.Chmod(dir, 0700) })
	}

	t.Run("CreateOutgoingShare", func(t *testing.T) {
		dir := testutil.TempDataDir(t, "ocm-test-json-rollback-create-out-share-*")

		d := makeDriver(t, dir)
		defer d.Close()

		share := testutil.NewOutgoingShareFixture()

		lockDir(t, dir)

		if err := d.(store.OutgoingShareStore).CreateOutgoingShare(ctx, share); err == nil {
			t.Fatal("expected error from CreateOutgoingShare with read-only dir, got nil")
		}

		// Restore write permission and verify primary record and all secondary
		// indexes are absent (rollback succeeded).
		os.Chmod(dir, 0700)

		if _, err := d.(store.OutgoingShareStore).GetOutgoingShare(ctx, share.ProviderId); err == nil {
			t.Error("share found in memory after failed create - rollback did not occur")
		}

		if _, err := d.(store.OutgoingShareStore).GetOutgoingShareByID(ctx, share.ShareId); err == nil {
			t.Error("shareId index not rolled back after failed create")
		}

		if _, err := d.(store.OutgoingShareStore).GetOutgoingShareByWebDAVId(ctx, share.WebDAVId); err == nil {
			t.Error("webdavId index not rolled back after failed create")
		}

		if _, err := d.(store.OutgoingShareStore).GetOutgoingShareBySharedSecret(ctx, share.SharedSecret); err == nil {
			t.Error("sharedSecret index not rolled back after failed create")
		}
	})

	t.Run("UpdateOutgoingShare", func(t *testing.T) {
		dir := testutil.TempDataDir(t, "ocm-test-json-rollback-update-out-share-*")

		d := makeDriver(t, dir)
		defer d.Close()

		share := testutil.NewOutgoingShareFixture()
		if err := d.(store.OutgoingShareStore).CreateOutgoingShare(ctx, share); err != nil {
			t.Fatalf("setup CreateOutgoingShare: %v", err)
		}

		// Use distinct new values for all three index fields so we can verify
		// neither the primary record nor any index entry was swapped.
		updated := *share
		updated.ShareId = "new-share-id"
		updated.WebDAVId = "new-webdav-id"
		updated.SharedSecret = "new-secret"
		updated.State = "accepted"

		lockDir(t, dir)

		if err := d.(store.OutgoingShareStore).UpdateOutgoingShare(ctx, &updated); err == nil {
			t.Fatal("expected error from UpdateOutgoingShare with read-only dir, got nil")
		}

		// Restore and verify the old record and all old indexes are intact.
		os.Chmod(dir, 0700)

		got, err := d.(store.OutgoingShareStore).GetOutgoingShare(ctx, share.ProviderId)
		if err != nil {
			t.Fatalf("share missing after failed update: %v", err)
		}

		if got.State != share.State {
			t.Errorf(
				"in-memory state changed after failed update: got %q, want %q",
				got.State,
				share.State,
			)
		}

		if got.ShareId != share.ShareId {
			t.Errorf(
				"in-memory shareId changed after failed update: got %q, want %q",
				got.ShareId,
				share.ShareId,
			)
		}
		// Old indexes must still resolve.
		if _, err := d.(store.OutgoingShareStore).GetOutgoingShareByID(ctx, share.ShareId); err != nil {
			t.Error("old shareId index entry missing after failed update rollback")
		}

		if _, err := d.(store.OutgoingShareStore).GetOutgoingShareByWebDAVId(ctx, share.WebDAVId); err != nil {
			t.Error("old webdavId index entry missing after failed update rollback")
		}

		if _, err := d.(store.OutgoingShareStore).GetOutgoingShareBySharedSecret(ctx, share.SharedSecret); err != nil {
			t.Error("old sharedSecret index entry missing after failed update rollback")
		}
		// New indexes must NOT resolve.
		if _, err := d.(store.OutgoingShareStore).GetOutgoingShareByID(ctx, updated.ShareId); err == nil {
			t.Error("new shareId index entry present after failed update - rollback incomplete")
		}

		if _, err := d.(store.OutgoingShareStore).GetOutgoingShareByWebDAVId(ctx, updated.WebDAVId); err == nil {
			t.Error("new webdavId index entry present after failed update - rollback incomplete")
		}

		if _, err := d.(store.OutgoingShareStore).GetOutgoingShareBySharedSecret(ctx, updated.SharedSecret); err == nil {
			t.Error("new sharedSecret index entry present after failed update - rollback incomplete")
		}
	})

	t.Run("DeleteOutgoingShare", func(t *testing.T) {
		dir := testutil.TempDataDir(t, "ocm-test-json-rollback-delete-out-share-*")

		d := makeDriver(t, dir)
		defer d.Close()

		share := testutil.NewOutgoingShareFixture()
		if err := d.(store.OutgoingShareStore).CreateOutgoingShare(ctx, share); err != nil {
			t.Fatalf("setup CreateOutgoingShare: %v", err)
		}

		lockDir(t, dir)

		if err := d.(store.OutgoingShareStore).DeleteOutgoingShare(ctx, share.ProviderId); err == nil {
			t.Fatal("expected error from DeleteOutgoingShare with read-only dir, got nil")
		}

		// Restore and verify the share and all indexes are still present.
		os.Chmod(dir, 0700)

		if _, err := d.(store.OutgoingShareStore).GetOutgoingShare(ctx, share.ProviderId); err != nil {
			t.Errorf("share missing after failed delete - rollback did not occur: %v", err)
		}

		if _, err := d.(store.OutgoingShareStore).GetOutgoingShareByID(ctx, share.ShareId); err != nil {
			t.Error("shareId index entry missing after failed delete rollback")
		}

		if _, err := d.(store.OutgoingShareStore).GetOutgoingShareByWebDAVId(ctx, share.WebDAVId); err != nil {
			t.Error("webdavId index entry missing after failed delete rollback")
		}

		if _, err := d.(store.OutgoingShareStore).GetOutgoingShareBySharedSecret(ctx, share.SharedSecret); err != nil {
			t.Error("sharedSecret index entry missing after failed delete rollback")
		}
	})

	t.Run("CreateIncomingShare", func(t *testing.T) {
		dir := testutil.TempDataDir(t, "ocm-test-json-rollback-create-in-share-*")

		d := makeDriver(t, dir)
		defer d.Close()

		share := testutil.NewIncomingShareFixture()

		lockDir(t, dir)

		if err := d.(store.IncomingShareStore).CreateIncomingShare(ctx, share); err == nil {
			t.Fatal("expected error from CreateIncomingShare with read-only dir, got nil")
		}

		os.Chmod(dir, 0700)

		if _, err := d.(store.IncomingShareStore).GetIncomingShareByIDForRecipient(
			ctx, share.ShareId, share.UserId,
		); err == nil {
			t.Error("incoming share found in memory after failed create - rollback did not occur")
		}

		if _, err := d.(store.IncomingShareStore).GetIncomingShareByProviderKey(
			ctx, share.SendingServer, share.ProviderId,
		); err == nil {
			t.Error("provider-key index not rolled back after failed create")
		}
	})

	t.Run("UpdateIncomingShareStatusForRecipient", func(t *testing.T) {
		dir := testutil.TempDataDir(t, "ocm-test-json-rollback-update-in-share-*")

		d := makeDriver(t, dir)
		defer d.Close()

		share := testutil.NewIncomingShareFixture()
		if err := d.(store.IncomingShareStore).CreateIncomingShare(ctx, share); err != nil {
			t.Fatalf("setup CreateIncomingShare: %v", err)
		}

		oldState := share.State
		oldUpdatedAt := share.UpdatedAt

		lockDir(t, dir)

		if err := d.(store.IncomingShareStore).UpdateIncomingShareStatusForRecipient(
			ctx, share.ShareId, share.UserId, "accepted",
		); err == nil {
			t.Fatal("expected error from UpdateIncomingShareStatusForRecipient with read-only dir, got nil")
		}

		// Restore and verify both State and UpdatedAt reverted (rollback succeeded).
		os.Chmod(dir, 0700)

		got, err := d.(store.IncomingShareStore).GetIncomingShareByIDForRecipient(
			ctx, share.ShareId, share.UserId,
		)
		if err != nil {
			t.Fatalf("share missing after failed status update: %v", err)
		}

		if got.State != oldState {
			t.Errorf(
				"in-memory state changed after failed update: got %q, want %q",
				got.State,
				oldState,
			)
		}

		if got.UpdatedAt != oldUpdatedAt {
			t.Errorf(
				"in-memory UpdatedAt changed after failed update: got %d, want %d",
				got.UpdatedAt,
				oldUpdatedAt,
			)
		}
	})

	t.Run("DeleteIncomingShareForRecipient", func(t *testing.T) {
		dir := testutil.TempDataDir(t, "ocm-test-json-rollback-delete-in-share-*")

		d := makeDriver(t, dir)
		defer d.Close()

		share := testutil.NewIncomingShareFixture()
		if err := d.(store.IncomingShareStore).CreateIncomingShare(ctx, share); err != nil {
			t.Fatalf("setup CreateIncomingShare: %v", err)
		}

		lockDir(t, dir)

		if err := d.(store.IncomingShareStore).DeleteIncomingShareForRecipient(
			ctx, share.ShareId, share.UserId,
		); err == nil {
			t.Fatal("expected error from DeleteIncomingShareForRecipient with read-only dir, got nil")
		}

		// Restore and verify the share and provider-key index are still present.
		os.Chmod(dir, 0700)

		if _, err := d.(store.IncomingShareStore).GetIncomingShareByIDForRecipient(
			ctx, share.ShareId, share.UserId,
		); err != nil {
			t.Errorf("share missing after failed delete - rollback did not occur: %v", err)
		}

		if _, err := d.(store.IncomingShareStore).GetIncomingShareByProviderKey(
			ctx, share.SendingServer, share.ProviderId,
		); err != nil {
			t.Error("provider-key index entry missing after failed delete rollback")
		}
	})
}
