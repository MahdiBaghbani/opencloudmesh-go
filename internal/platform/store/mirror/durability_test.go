package mirror_test

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/mirror"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

// TestMirrorInviteReopenDurability verifies that both invite surfaces persist
// and reload correctly through the store API after the mirror driver is closed
// and reopened. Export artifact presence is covered separately in export_test.go.
func TestMirrorInviteReopenDurability(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-mirror-invite-reopen-*")

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
	}

	// Create both invite surfaces.
	driver := testutil.OpenDriver(t, cfg)

	outInvite := testutil.NewOutgoingInviteFixture()
	outInvite.ID = "mirror-outgoing-invite-reopen"
	outInvite.Token = "mirror-outgoing-token-reopen"
	if err := driver.(store.OutgoingInviteStore).CreateOutgoingInvite(ctx, outInvite); err != nil {
		t.Fatalf("CreateOutgoingInvite: %v", err)
	}

	inInvite := testutil.NewIncomingInviteFixture()
	inInvite.ID = "mirror-incoming-invite-reopen"
	inInvite.Token = "mirror-incoming-token-reopen"
	inInvite.RecipientUserId = "mirror-recipient"
	if err := driver.(store.IncomingInviteStore).CreateIncomingInvite(ctx, inInvite); err != nil {
		t.Fatalf("CreateIncomingInvite: %v", err)
	}
	driver.Close()

	// Reopen the driver and verify both invites survived via store API.
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
