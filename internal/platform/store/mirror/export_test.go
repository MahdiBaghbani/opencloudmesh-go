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
		Mirror: store.MirrorConfig{
			IncludeSecrets: false,
			SecretsScope:   []string{},
		},
	}

	driver := testutil.OpenDriver(t, cfg)

	outStore := driver.(store.OutgoingShareStore)

	// Create a share with a secret
	share := testutil.NewOutgoingShareFixture()
	share.SharedSecret = "my-secret-value"
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatal(err)
	}

	// Read the JSON export
	jsonPath := filepath.Join(tempDir, "mirror", "outgoing_shares.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}

	// Secret should NOT be in the JSON
	if string(data) != "[]" && strings.Contains(string(data), "my-secret-value") {
		t.Error("secret was exported to JSON when IncludeSecrets=false")
	}

	driver.Close()
}

func TestMirrorDriverSecretExport(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-mirror-export-*")

	ctx := context.Background()

	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
		Mirror: store.MirrorConfig{
			IncludeSecrets: true,
			SecretsScope:   []string{"webdav_shared_secrets"},
		},
	}

	driver := testutil.OpenDriver(t, cfg)

	outStore := driver.(store.OutgoingShareStore)

	// Create a share with a secret
	share := testutil.NewOutgoingShareFixture()
	share.SharedSecret = "exported-secret"
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatal(err)
	}

	// Read the JSON export
	jsonPath := filepath.Join(tempDir, "mirror", "outgoing_shares.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}

	// Secret SHOULD be in the JSON
	if !strings.Contains(string(data), "exported-secret") {
		t.Error("secret was NOT exported to JSON when IncludeSecrets=true and scope allows")
	}

	driver.Close()
}

// TestMirrorInviteExportOnInit verifies that Init exports both invite surfaces
// to JSON and that rows created in a prior session appear in the exported files
// after a close/reopen cycle.
func TestMirrorInviteExportOnInit(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-mirror-invite-*")

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
	}

	// First open: create both invite types through the store interface, then close.
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

	// Second open: Init exports all surfaces from SQLite to JSON.
	driver2 := testutil.OpenDriver(t, cfg)
	defer driver2.Close()

	mirrorDir := filepath.Join(tempDir, "mirror")

	outData, err := os.ReadFile(filepath.Join(mirrorDir, "outgoing_invites.json"))
	if err != nil {
		t.Fatalf("outgoing_invites.json missing after reopen: %v", err)
	}
	if !strings.Contains(string(outData), outInvite.Token) {
		t.Errorf("outgoing_invites.json missing token %q; content: %s", outInvite.Token, outData)
	}

	inData, err := os.ReadFile(filepath.Join(mirrorDir, "incoming_invites.json"))
	if err != nil {
		t.Fatalf("incoming_invites.json missing after reopen: %v", err)
	}
	if !strings.Contains(string(inData), inInvite.Token) {
		t.Errorf("incoming_invites.json missing token %q; content: %s", inInvite.Token, inData)
	}
}
