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

	shareStore := driver.(store.ShareStore)

	// Create a share with a secret
	share := testutil.TestOutgoingShare()
	share.SharedSecret = "my-secret-value"
	if err := shareStore.CreateOutgoingShare(ctx, share); err != nil {
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

	shareStore := driver.(store.ShareStore)

	// Create a share with a secret
	share := testutil.TestOutgoingShare()
	share.SharedSecret = "exported-secret"
	if err := shareStore.CreateOutgoingShare(ctx, share); err != nil {
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

	shareStore := driver.(store.ShareStore)

	// Create a share
	share := testutil.TestOutgoingShare()
	if err := shareStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatal(err)
	}
	driver.Close()

	// Corrupt the JSON file
	jsonPath := filepath.Join(tempDir, "mirror", "outgoing_shares.json")
	os.WriteFile(jsonPath, []byte("CORRUPTED"), 0600)

	// Reload driver - should still work because it reads from SQLite, not JSON
	driver2, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer driver2.Close()

	shareStore2 := driver2.(store.ShareStore)
	got, err := shareStore2.GetOutgoingShare(ctx, share.ProviderId)
	if err != nil {
		t.Fatalf("mirror driver read from JSON instead of SQLite: %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("data corruption: expected %q, got %q", share.ProviderId, got.ProviderId)
	}
}
