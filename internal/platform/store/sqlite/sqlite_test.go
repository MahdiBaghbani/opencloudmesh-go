package sqlite_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/testutil"
)

func TestSQLiteDriver(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-sqlite-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &store.DriverConfig{
		Driver:  "sqlite",
		DataDir: tempDir,
	}

	testutil.RunDriverTests(t, "sqlite", cfg)

	// Verify database file was created
	if _, err := os.Stat(filepath.Join(tempDir, "ocm.db")); os.IsNotExist(err) {
		t.Error("ocm.db not created")
	}
}

func TestSQLiteDriverSurvivesRestart(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-sqlite-restart-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "sqlite",
		DataDir: tempDir,
	}

	driver, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Init(ctx); err != nil {
		t.Fatal(err)
	}

	outStore := driver.(store.OutgoingShareStore)

	// Create a share
	share := testutil.NewOutgoingShareFixture()
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatal(err)
	}
	driver.Close()

	// Reload driver - data should survive
	driver2, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver2.Init(ctx); err != nil {
		t.Fatal(err)
	}
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
	tempDir, err := os.MkdirTemp("", "ocm-test-sqlite-invite-reopen-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "sqlite",
		DataDir: tempDir,
	}

	// First open: create both invite types through the store interface.
	driver, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Init(ctx); err != nil {
		t.Fatalf("first init failed: %v", err)
	}

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
	driver2, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver2.Init(ctx); err != nil {
		t.Fatalf("second init failed: %v", err)
	}
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
}
