package sqlite_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/store/sqlite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/store/testutil"
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
