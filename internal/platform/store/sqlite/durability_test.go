package sqlite_test

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/testutil"
)

func TestSQLiteDriverSurvivesRestart(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-sqlite-restart-*")

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "sqlite",
		DataDir: tempDir,
	}

	driver := testutil.OpenDriver(t, cfg)

	outStore := driver.(store.OutgoingShareStore)

	// Create a share
	share := testutil.NewOutgoingShareFixture()
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatal(err)
	}
	driver.Close()

	// Reload driver - data should survive
	driver2 := testutil.OpenDriver(t, cfg)
	defer driver2.Close()

	outStore2 := driver2.(store.OutgoingShareStore)
	got, err := outStore2.GetOutgoingShare(ctx, share.ProviderId)
	if err != nil {
		t.Fatalf("share not found after restart: %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("data corruption: expected %q, got %q", share.ProviderId, got.ProviderId)
	}
}

// TestSQLiteInviteReopenDurability verifies that both invite surfaces persist
// across a driver close/reopen cycle when created through the store interface.
func TestSQLiteInviteReopenDurability(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-sqlite-invite-reopen-*")

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "sqlite",
		DataDir: tempDir,
	}

	// First open: create both invite types through the store interface.
	driver := testutil.OpenDriver(t, cfg)

	outInvStore := driver.(store.OutgoingInviteStore)
	inInvStore := driver.(store.IncomingInviteStore)

	outInvite := testutil.NewOutgoingInviteFixture()
	outInvite.ID = "sqlite-outgoing-invite-reopen"
	outInvite.Token = "sqlite-outgoing-token-reopen"
	if err := outInvStore.CreateOutgoingInvite(ctx, outInvite); err != nil {
		t.Fatalf("create outgoing invite: %v", err)
	}

	inInvite := testutil.NewIncomingInviteFixture()
	inInvite.ID = "sqlite-incoming-invite-reopen"
	inInvite.Token = "sqlite-incoming-token-reopen"
	inInvite.RecipientUserId = "sqlite-recipient"
	if err := inInvStore.CreateIncomingInvite(ctx, inInvite); err != nil {
		t.Fatalf("create incoming invite: %v", err)
	}

	if err := driver.Close(); err != nil {
		t.Fatalf("close after first session: %v", err)
	}

	// Second open: verify both invite rows persisted through the store API.
	driver2 := testutil.OpenDriver(t, cfg)
	defer driver2.Close()

	outInvStore2 := driver2.(store.OutgoingInviteStore)
	gotOut, err := outInvStore2.GetOutgoingInvite(ctx, outInvite.ID)
	if err != nil {
		t.Fatalf("reload outgoing invite via store: %v", err)
	}
	if gotOut.Token != outInvite.Token {
		t.Errorf("outgoing invite token mismatch after reopen: expected %q, got %q",
			outInvite.Token, gotOut.Token)
	}

	inInvStore2 := driver2.(store.IncomingInviteStore)
	gotIn, err := inInvStore2.GetIncomingInviteForRecipient(ctx, inInvite.ID, inInvite.RecipientUserId)
	if err != nil {
		t.Fatalf("reload incoming invite via store: %v", err)
	}
	if gotIn.Token != inInvite.Token {
		t.Errorf("incoming invite token mismatch after reopen: expected %q, got %q",
			inInvite.Token, gotIn.Token)
	}
	if gotIn.RecipientUserId != inInvite.RecipientUserId {
		t.Errorf("incoming invite recipient mismatch after reopen: expected %q, got %q",
			inInvite.RecipientUserId, gotIn.RecipientUserId)
	}

	// Token-based lookup must also survive the restart.
	gotByTok, err := outInvStore2.GetOutgoingInviteByToken(ctx, outInvite.Token)
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

	gotInByTok, err := inInvStore2.GetIncomingInviteByToken(
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
