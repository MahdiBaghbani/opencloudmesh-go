package sqlite_test

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlite"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

func TestSQLiteDriverSurvivesRestart(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-sqlite-restart-*")

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "sqlite",
		DataDir: tempDir,
	}

	driver := testutil.OpenDriver(t, cfg)

	outStore := driver.(store.OutgoingShareStore)

	// Create a share
	share := testutil.NewOutgoingShareFixture()
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatal(err)
	}
	driver.Close()

	// Reload driver - data should survive
	driver2 := testutil.OpenDriver(t, cfg)
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
