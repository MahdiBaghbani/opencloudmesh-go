package json_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/store/json"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/store/testutil"
)

func TestJSONDriver(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-json-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &store.DriverConfig{
		Driver:  "json",
		DataDir: tempDir,
	}

	testutil.RunDriverTests(t, "json", cfg)

	// Verify JSON files were created
	if _, err := os.Stat(filepath.Join(tempDir, "outgoing_shares.json")); os.IsNotExist(err) {
		t.Log("outgoing_shares.json not created (expected if no shares remain)")
	}
}

func TestJSONDriverAtomicWrite(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-json-atomic-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "json",
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

	// Reload driver - data should survive
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
		t.Fatalf("share not found after restart: %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("data corruption: expected %q, got %q", share.ProviderId, got.ProviderId)
	}
}
