package json_test

import (
	"context"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/testutil"
)

// TestJSONInviteReopenDurability verifies that both invite surfaces persist
// and reload correctly after the JSON driver is closed and reopened.
func TestJSONInviteReopenDurability(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-json-invite-reopen-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	cfg := &store.DriverConfig{Driver: "json", DataDir: tempDir}

	// Phase 1: create both invite surfaces.
	driver, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Init(ctx); err != nil {
		t.Fatal(err)
	}

	outInvite := testutil.NewOutgoingInviteFixture()
	if err := driver.(store.OutgoingInviteStore).CreateOutgoingInvite(ctx, outInvite); err != nil {
		t.Fatalf("CreateOutgoingInvite: %v", err)
	}

	inInvite := testutil.NewIncomingInviteFixture()
	if err := driver.(store.IncomingInviteStore).CreateIncomingInvite(ctx, inInvite); err != nil {
		t.Fatalf("CreateIncomingInvite: %v", err)
	}
	driver.Close()

	// Phase 2: reopen and verify both invites survived.
	driver2, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer driver2.Close()

	gotOut, err := driver2.(store.OutgoingInviteStore).GetOutgoingInvite(ctx, outInvite.ID)
	if err != nil {
		t.Fatalf("outgoing invite not found after restart: %v", err)
	}
	if gotOut.Token != outInvite.Token {
		t.Errorf(
			"outgoing invite token mismatch: expected %q, got %q",
			outInvite.Token,
			gotOut.Token,
		)
	}

	gotIn, err := driver2.(store.IncomingInviteStore).GetIncomingInviteForRecipient(
		ctx, inInvite.ID, inInvite.RecipientUserId,
	)
	if err != nil {
		t.Fatalf("incoming invite not found after restart: %v", err)
	}
	if gotIn.Token != inInvite.Token {
		t.Errorf(
			"incoming invite token mismatch: expected %q, got %q",
			inInvite.Token,
			gotIn.Token,
		)
	}

	// Token-based lookup must also survive the restart.
	gotByTok, err := driver2.(store.OutgoingInviteStore).GetOutgoingInviteByToken(ctx, outInvite.Token)
	if err != nil {
		t.Fatalf("outgoing invite token index not rebuilt after restart: %v", err)
	}
	if gotByTok.ID != outInvite.ID {
		t.Errorf(
			"outgoing invite token index mismatch: expected %q, got %q",
			outInvite.ID,
			gotByTok.ID,
		)
	}

	gotInByTok, err := driver2.(store.IncomingInviteStore).GetIncomingInviteByToken(
		ctx, inInvite.Token, inInvite.RecipientUserId,
	)
	if err != nil {
		t.Fatalf("incoming invite token-user index not rebuilt after restart: %v", err)
	}
	if gotInByTok.ID != inInvite.ID {
		t.Errorf(
			"incoming invite token-user index mismatch: expected %q, got %q",
			inInvite.ID,
			gotInByTok.ID,
		)
	}
}

// TestJSONInviteSaveFailureRollback verifies that when saveFile fails the
// in-memory state is not left in a mutated state (no split-brain).
// The failure is injected by making the data directory read-only after Init.
func TestJSONInviteSaveFailureRollback(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("cannot test read-only dir as root")
	}

	ctx := context.Background()

	makeDriver := func(t *testing.T, dir string) store.Driver {
		t.Helper()
		cfg := &store.DriverConfig{Driver: "json", DataDir: dir}
		d, err := store.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Init(ctx); err != nil {
			t.Fatal(err)
		}
		return d
	}

	lockDir := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.Chmod(dir, 0500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0700) })
	}

	t.Run("CreateOutgoingInvite", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "ocm-test-json-rollback-create-out-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		d := makeDriver(t, dir)
		defer d.Close()

		invite := testutil.NewOutgoingInviteFixture()
		lockDir(t, dir)

		if err := d.(store.OutgoingInviteStore).CreateOutgoingInvite(ctx, invite); err == nil {
			t.Fatal("expected error from CreateOutgoingInvite with read-only dir, got nil")
		}

		// Restore write permission and verify the invite is NOT in-memory (rollback succeeded).
		os.Chmod(dir, 0700)
		if _, err := d.(store.OutgoingInviteStore).GetOutgoingInvite(ctx, invite.ID); err == nil {
			t.Error("invite found in memory after failed create - rollback did not occur")
		}
		if _, err := d.(store.OutgoingInviteStore).GetOutgoingInviteByToken(ctx, invite.Token); err == nil {
			t.Error("invite token index not rolled back after failed create")
		}
	})

	t.Run("UpdateOutgoingInvite", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "ocm-test-json-rollback-update-out-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		d := makeDriver(t, dir)
		defer d.Close()

		invite := testutil.NewOutgoingInviteFixture()
		if err := d.(store.OutgoingInviteStore).CreateOutgoingInvite(ctx, invite); err != nil {
			t.Fatalf("setup CreateOutgoingInvite: %v", err)
		}

		updated := *invite
		updated.Token = "new-token"

		lockDir(t, dir)

		if err := d.(store.OutgoingInviteStore).UpdateOutgoingInvite(ctx, &updated); err == nil {
			t.Fatal("expected error from UpdateOutgoingInvite with read-only dir, got nil")
		}

		// Restore and verify the old value is still present (rollback succeeded).
		os.Chmod(dir, 0700)
		got, err := d.(store.OutgoingInviteStore).GetOutgoingInvite(ctx, invite.ID)
		if err != nil {
			t.Fatalf("invite missing after failed update: %v", err)
		}
		if got.Token != invite.Token {
			t.Errorf(
				"in-memory token changed after failed update: got %q, want %q",
				got.Token,
				invite.Token,
			)
		}
		if _, err := d.(store.OutgoingInviteStore).GetOutgoingInviteByToken(ctx, invite.Token); err != nil {
			t.Error("old token index entry missing after failed update rollback")
		}
		if _, err := d.(store.OutgoingInviteStore).GetOutgoingInviteByToken(ctx, updated.Token); err == nil {
			t.Error("new token index entry present after failed update - rollback incomplete")
		}
	})

	t.Run("DeleteOutgoingInvite", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "ocm-test-json-rollback-delete-out-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		d := makeDriver(t, dir)
		defer d.Close()

		invite := testutil.NewOutgoingInviteFixture()
		if err := d.(store.OutgoingInviteStore).CreateOutgoingInvite(ctx, invite); err != nil {
			t.Fatalf("setup CreateOutgoingInvite: %v", err)
		}

		lockDir(t, dir)

		if err := d.(store.OutgoingInviteStore).DeleteOutgoingInvite(ctx, invite.ID); err == nil {
			t.Fatal("expected error from DeleteOutgoingInvite with read-only dir, got nil")
		}

		// Restore and verify the invite is still present (rollback succeeded).
		os.Chmod(dir, 0700)
		if _, err := d.(store.OutgoingInviteStore).GetOutgoingInvite(ctx, invite.ID); err != nil {
			t.Errorf("invite missing after failed delete - rollback did not occur: %v", err)
		}
		if _, err := d.(store.OutgoingInviteStore).GetOutgoingInviteByToken(ctx, invite.Token); err != nil {
			t.Error("token index entry missing after failed delete rollback")
		}
	})

	t.Run("CreateIncomingInvite", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "ocm-test-json-rollback-create-in-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		d := makeDriver(t, dir)
		defer d.Close()

		invite := testutil.NewIncomingInviteFixture()
		lockDir(t, dir)

		if err := d.(store.IncomingInviteStore).CreateIncomingInvite(ctx, invite); err == nil {
			t.Fatal("expected error from CreateIncomingInvite with read-only dir, got nil")
		}

		os.Chmod(dir, 0700)
		if _, err := d.(store.IncomingInviteStore).GetIncomingInviteForRecipient(
			ctx, invite.ID, invite.RecipientUserId,
		); err == nil {
			t.Error("incoming invite found in memory after failed create - rollback did not occur")
		}
		if _, err := d.(store.IncomingInviteStore).GetIncomingInviteByToken(
			ctx, invite.Token, invite.RecipientUserId,
		); err == nil {
			t.Error("incoming invite token index not rolled back after failed create")
		}
	})

	t.Run("UpdateIncomingInviteStatusForRecipient", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "ocm-test-json-rollback-update-in-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		d := makeDriver(t, dir)
		defer d.Close()

		invite := testutil.NewIncomingInviteFixture()
		if err := d.(store.IncomingInviteStore).CreateIncomingInvite(ctx, invite); err != nil {
			t.Fatalf("setup CreateIncomingInvite: %v", err)
		}

		oldStatus := invite.Status
		lockDir(t, dir)

		if err := d.(store.IncomingInviteStore).UpdateIncomingInviteStatusForRecipient(
			ctx, invite.ID, invite.RecipientUserId, "new-status",
		); err == nil {
			t.Fatal("expected error from UpdateIncomingInviteStatusForRecipient with read-only dir, got nil")
		}

		os.Chmod(dir, 0700)
		got, err := d.(store.IncomingInviteStore).GetIncomingInviteForRecipient(
			ctx, invite.ID, invite.RecipientUserId,
		)
		if err != nil {
			t.Fatalf("invite missing after failed status update: %v", err)
		}
		if got.Status != oldStatus {
			t.Errorf(
				"in-memory status changed after failed update: got %q, want %q",
				got.Status,
				oldStatus,
			)
		}
	})

	t.Run("DeleteIncomingInviteForRecipient", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "ocm-test-json-rollback-delete-in-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		d := makeDriver(t, dir)
		defer d.Close()

		invite := testutil.NewIncomingInviteFixture()
		if err := d.(store.IncomingInviteStore).CreateIncomingInvite(ctx, invite); err != nil {
			t.Fatalf("setup CreateIncomingInvite: %v", err)
		}

		lockDir(t, dir)

		if err := d.(store.IncomingInviteStore).DeleteIncomingInviteForRecipient(
			ctx, invite.ID, invite.RecipientUserId,
		); err == nil {
			t.Fatal("expected error from DeleteIncomingInviteForRecipient with read-only dir, got nil")
		}

		os.Chmod(dir, 0700)
		if _, err := d.(store.IncomingInviteStore).GetIncomingInviteForRecipient(
			ctx, invite.ID, invite.RecipientUserId,
		); err != nil {
			t.Errorf("invite missing after failed delete - rollback did not occur: %v", err)
		}
		if _, err := d.(store.IncomingInviteStore).GetIncomingInviteByToken(
			ctx, invite.Token, invite.RecipientUserId,
		); err != nil {
			t.Error("token-user index entry missing after failed delete rollback")
		}
	})
}

// TestJSONShareSaveFailureRollback verifies that when saveFile fails the
// in-memory share state is not left in a mutated state (no split-brain).
// The failure is injected by making the data directory read-only after Init,
// mirroring the pattern used by TestJSONInviteSaveFailureRollback.
func TestJSONShareSaveFailureRollback(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("cannot test read-only dir as root")
	}

	ctx := context.Background()

	makeDriver := func(t *testing.T, dir string) store.Driver {
		t.Helper()
		cfg := &store.DriverConfig{Driver: "json", DataDir: dir}
		d, err := store.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Init(ctx); err != nil {
			t.Fatal(err)
		}
		return d
	}

	lockDir := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.Chmod(dir, 0500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0700) })
	}

	t.Run("CreateOutgoingShare", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "ocm-test-json-rollback-create-out-share-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

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
		dir, err := os.MkdirTemp("", "ocm-test-json-rollback-update-out-share-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

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
		dir, err := os.MkdirTemp("", "ocm-test-json-rollback-delete-out-share-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

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
		dir, err := os.MkdirTemp("", "ocm-test-json-rollback-create-in-share-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

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
		dir, err := os.MkdirTemp("", "ocm-test-json-rollback-update-in-share-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

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
		dir, err := os.MkdirTemp("", "ocm-test-json-rollback-delete-in-share-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

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
