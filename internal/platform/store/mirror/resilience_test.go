package mirror_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/mirror"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

// TestMirrorExportFailureTransparentToCallers verifies that a write mutator
// returns nil even when the JSON export step fails. SQLite is the source of
// truth; an export failure must not surface as a write error to the caller.
// The test injects the failure by making the mirror directory read-only after
// Init, so that temp-file creation inside writeJSON fails.
func TestMirrorExportFailureTransparentToCallers(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("cannot test read-only dir as root")
	}

	tempDir := testutil.TempDataDir(t, "ocm-test-mirror-exportfail-*")

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
	}

	driver := testutil.OpenDriver(t, cfg)
	defer driver.Close() //nolint:errcheck // test cleanup: driver close

	// Make the mirror dir read-only so all subsequent JSON export attempts fail.
	mirrorDir := filepath.Join(tempDir, "mirror")
	if err := os.Chmod(mirrorDir, 0500); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		os.Chmod(mirrorDir, 0700) //nolint:errcheck // test cleanup: restore directory permissions
	})

	outStore := requireOutgoingShareStore(t, driver)
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
	tempDir := testutil.TempDataDir(t, "ocm-test-mirror-noread-*")

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
	}

	driver := testutil.OpenDriver(t, cfg)

	outStore := requireOutgoingShareStore(t, driver)

	// Create a share
	share := testutil.NewOutgoingShareFixture()
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatal(err)
	}

	driver.Close() //nolint:errcheck // test cleanup: driver close

	// Corrupt the JSON file
	jsonPath := filepath.Join(tempDir, "mirror", "outgoing_shares.json")
	if err := os.WriteFile(jsonPath, []byte("CORRUPTED"), 0600); err != nil {
		t.Fatalf("failed to corrupt JSON file: %v", err)
	}

	// Reload driver - should still work because it reads from SQLite, not JSON
	driver2 := testutil.OpenDriver(t, cfg)
	defer driver2.Close() //nolint:errcheck // test cleanup: driver close

	outStore2 := requireOutgoingShareStore(t, driver2)

	got, err := outStore2.GetOutgoingShare(ctx, share.ProviderId)
	if err != nil {
		t.Fatalf("mirror driver read from JSON instead of SQLite: %v", err)
	}

	if got.ProviderId != share.ProviderId {
		t.Errorf("data corruption: expected %q, got %q", share.ProviderId, got.ProviderId)
	}
}
