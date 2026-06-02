package mirror_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/mirror"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/testutil"
)

func TestMirrorDriver(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-mirror-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
		Mirror: store.MirrorConfig{
			IncludeSecrets: false,
			SecretsScope:   []string{},
		},
	}

	testutil.RunDriverTests(t, "mirror", cfg)

	// Verify both database and mirror files exist
	if _, err := os.Stat(filepath.Join(tempDir, "ocm.db")); os.IsNotExist(err) {
		t.Error("ocm.db not created")
	}
	if _, err := os.Stat(filepath.Join(tempDir, "mirror")); os.IsNotExist(err) {
		t.Error("mirror directory not created")
	}
}

func TestMirrorDriverSecretRedaction(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-mirror-redact-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()

	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
		Mirror: store.MirrorConfig{
			IncludeSecrets: false,
			SecretsScope:   []string{},
		},
	}

	driver, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Init(ctx); err != nil {
		t.Fatal(err)
	}

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
	tempDir, err := os.MkdirTemp("", "ocm-test-mirror-export-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()

	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
		Mirror: store.MirrorConfig{
			IncludeSecrets: true,
			SecretsScope:   []string{"webdav_shared_secrets"},
		},
	}

	driver, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Init(ctx); err != nil {
		t.Fatal(err)
	}

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
	tempDir, err := os.MkdirTemp("", "ocm-test-mirror-invite-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
	}

	// First open: create both invite types through the store interface, then close.
	driver, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Init(ctx); err != nil {
		t.Fatal(err)
	}

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
	driver2, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver2.Init(ctx); err != nil {
		t.Fatal(err)
	}
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

// TestMirrorExportFailureTransparentToCallers verifies that a write mutator
// returns nil even when the JSON export step fails. SQLite is the source of
// truth; an export failure must not surface as a write error to the caller.
// The test injects the failure by making the mirror directory read-only after
// Init, so that temp-file creation inside writeJSON fails.
func TestMirrorExportFailureTransparentToCallers(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("cannot test read-only dir as root")
	}

	tempDir, err := os.MkdirTemp("", "ocm-test-mirror-exportfail-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
	}

	driver, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer driver.Close()

	// Make the mirror dir read-only so all subsequent JSON export attempts fail.
	mirrorDir := filepath.Join(tempDir, "mirror")
	if err := os.Chmod(mirrorDir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(mirrorDir, 0700) })

	outStore := driver.(store.OutgoingShareStore)
	share := testutil.NewOutgoingShareFixture()

	// The mutator must return nil even though the export step fails.
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("CreateOutgoingShare returned error after SQLite commit: %v", err)
	}

	// SQLite must still have the record.
	got, err := outStore.GetOutgoingShare(ctx, share.ProviderId)
	if err != nil {
		t.Fatalf("GetOutgoingShare: %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("unexpected ProviderId: got %q, want %q", got.ProviderId, share.ProviderId)
	}

	// Restore write permission and verify a second write (update) also succeeds.
	if err := os.Chmod(mirrorDir, 0700); err != nil {
		t.Fatal(err)
	}
	share.Name = "updated-name"
	if err := outStore.UpdateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("UpdateOutgoingShare returned unexpected error: %v", err)
	}
}

func TestMirrorNeverReadsJSON(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-mirror-noread-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "mirror",
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

	// Corrupt the JSON file
	jsonPath := filepath.Join(tempDir, "mirror", "outgoing_shares.json")
	if err := os.WriteFile(jsonPath, []byte("CORRUPTED"), 0600); err != nil {
		t.Fatalf("failed to corrupt JSON file: %v", err)
	}

	// Reload driver - should still work because it reads from SQLite, not JSON
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
		t.Fatalf("mirror driver read from JSON instead of SQLite: %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("data corruption: expected %q, got %q", share.ProviderId, got.ProviderId)
	}
}
