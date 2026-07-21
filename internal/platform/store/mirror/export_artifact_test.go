package mirror_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/mirror"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

func TestMirrorDriverSecretRedaction(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-mirror-redact-*")

	ctx := context.Background()

	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
	}

	driver := testutil.OpenDriver(t, cfg)

	outStore := driver.(store.OutgoingShareStore)

	share := testutil.NewOutgoingShareFixture()
	share.SharedSecret = "my-secret-value"
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatal(err)
	}

	jsonPath := filepath.Join(tempDir, "mirror", "outgoing_shares.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != "[]" && strings.Contains(string(data), "my-secret-value") {
		t.Error("shared secret must not appear in mirror JSON export")
	}

	driver.Close()
}

// TestMirrorInviteExportOnInit verifies that Init exports both invite surfaces
// to JSON and redacts invite tokens from exported files.
func TestMirrorInviteExportOnInit(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-mirror-invite-*")

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
	}

	driver := testutil.OpenDriver(t, cfg)

	outInvite := testutil.NewOutgoingInviteFixture()
	outInvite.ID = "mirror-out-id"
	outInvite.Token = "mirror-out-token"
	if err := driver.(store.OutgoingInviteStore).CreateOutgoingInvite(ctx, outInvite); err != nil {
		t.Fatalf("create outgoing invite: %v", err)
	}

	inInvite := testutil.NewIncomingInviteFixture()
	inInvite.ID = "mirror-in-id"
	inInvite.Token = "mirror-in-token"
	if err := driver.(store.IncomingInviteStore).CreateIncomingInvite(ctx, inInvite); err != nil {
		t.Fatalf("create incoming invite: %v", err)
	}

	driver.Close()

	driver2 := testutil.OpenDriver(t, cfg)
	defer driver2.Close()

	mirrorDir := filepath.Join(tempDir, "mirror")

	outData, err := os.ReadFile(filepath.Join(mirrorDir, "outgoing_invites.json"))
	if err != nil {
		t.Fatalf("outgoing_invites.json missing after reopen: %v", err)
	}
	if strings.Contains(string(outData), outInvite.Token) {
		t.Errorf("outgoing_invites.json must not contain token %q", outInvite.Token)
	}

	inData, err := os.ReadFile(filepath.Join(mirrorDir, "incoming_invites.json"))
	if err != nil {
		t.Fatalf("incoming_invites.json missing after reopen: %v", err)
	}
	if strings.Contains(string(inData), inInvite.Token) {
		t.Errorf("incoming_invites.json must not contain token %q", inInvite.Token)
	}
}
