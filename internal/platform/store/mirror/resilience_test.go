// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package mirror_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/mirror"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

// TestMirrorExportFailureTransparentToCallers verifies that a write mutator
// returns nil even when the JSON export step fails. SQLite is the source of
// truth; an export failure must not surface as a write error to the caller.
// The test injects the failure by making the mirror directory read-only after
// Init, so that temp-file creation inside writeJSON fails.
func TestMirrorExportFailureTransparentToCallers(t *testing.T) {
	t.Parallel()

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
	defer tshttp.MustClose(t, driver)

	// Make the mirror dir read-only so all subsequent JSON export attempts fail.
	mirrorDir := filepath.Join(tempDir, "mirror")
	if err := os.Chmod(mirrorDir, 0500); err != nil { //nolint:gosec // test fixture: restrictive 0500 removes write permission on the temp dir to force store failures
		t.Fatal(err)
	}

	t.Cleanup(func() {
		restoreDirPerms(t, mirrorDir)
	})

	outStore := requireOutgoingShareStore(t, driver)
	share := testutil.NewOutgoingShareFixture()

	// The mutator must return nil even though the export step fails.
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("CreateOutgoingShare returned error after SQLite commit: %v", err)
	}

	// SQLite must still have the record.
	got, err := outStore.GetOutgoingShare(ctx, share.ProviderID)
	if err != nil {
		t.Fatalf("GetOutgoingShare: %v", err)
	}

	if got.ProviderID != share.ProviderID {
		t.Errorf("unexpected ProviderID: got %q, want %q", got.ProviderID, share.ProviderID)
	}

	// Restore write permission and verify a second write (update) also succeeds.
	if err := os.Chmod(mirrorDir, 0700); err != nil { //nolint:gosec // test fixture: restrictive 0700 restores write permission for the update-path check
		t.Fatal(err)
	}

	share.Name = "updated-name"
	if err := outStore.UpdateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("UpdateOutgoingShare returned unexpected error: %v", err)
	}
}

func TestMirrorNeverReadsJSON(t *testing.T) {
	t.Parallel()
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

	tshttp.MustClose(t, driver)

	// Corrupt the JSON file
	jsonPath := filepath.Join(tempDir, "mirror", "outgoing_shares.json")
	if err := os.WriteFile(jsonPath, []byte("CORRUPTED"), 0600); err != nil {
		t.Fatalf("failed to corrupt JSON file: %v", err)
	}

	// Reload driver - should still work because it reads from SQLite, not JSON
	driver2 := testutil.OpenDriver(t, cfg)
	defer tshttp.MustClose(t, driver2)

	outStore2 := requireOutgoingShareStore(t, driver2)

	got, err := outStore2.GetOutgoingShare(ctx, share.ProviderID)
	if err != nil {
		t.Fatalf("mirror driver read from JSON instead of SQLite: %v", err)
	}

	if got.ProviderID != share.ProviderID {
		t.Errorf("data corruption: expected %q, got %q", share.ProviderID, got.ProviderID)
	}
}
