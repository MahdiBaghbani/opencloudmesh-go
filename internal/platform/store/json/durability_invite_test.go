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
func TestJSONInviteReopenDurability(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-json-invite-reopen-*")

	ctx := context.Background()
	cfg := &store.DriverConfig{Driver: "json", DataDir: tempDir}

	// Create both invite surfaces.
	driver := testutil.OpenDriver(t, cfg)

	outInvite := testutil.NewOutgoingInviteFixture()
	if err := driver.(store.OutgoingInviteStore).CreateOutgoingInvite(ctx, outInvite); err != nil {
		t.Fatalf("CreateOutgoingInvite: %v", err)
	}

	inInvite := testutil.NewIncomingInviteFixture()
	if err := driver.(store.IncomingInviteStore).CreateIncomingInvite(ctx, inInvite); err != nil {
		t.Fatalf("CreateIncomingInvite: %v", err)
	}
	driver.Close()

	// Reopen the driver and verify both invites survived.
	driver2 := testutil.OpenDriver(t, cfg)
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
		return testutil.OpenDriver(t, cfg)
	}

	lockDir := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.Chmod(dir, 0500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0700) })
	}

	t.Run("CreateOutgoingInvite", func(t *testing.T) {
		dir := testutil.TempDataDir(t, "ocm-test-json-rollback-create-out-*")

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
		dir := testutil.TempDataDir(t, "ocm-test-json-rollback-update-out-*")

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
		dir := testutil.TempDataDir(t, "ocm-test-json-rollback-delete-out-*")

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
		dir := testutil.TempDataDir(t, "ocm-test-json-rollback-create-in-*")

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
		dir := testutil.TempDataDir(t, "ocm-test-json-rollback-update-in-*")

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
		dir := testutil.TempDataDir(t, "ocm-test-json-rollback-delete-in-*")

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
