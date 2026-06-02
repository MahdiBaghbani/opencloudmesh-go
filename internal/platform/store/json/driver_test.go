package json_test

import (
	"context"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/json"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/testutil"
)

func newJSONDriver(t *testing.T) (store.Driver, string) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "ocm-test-json-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })
	cfg := &store.DriverConfig{Driver: "json", DataDir: tempDir}
	d, err := store.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return d, tempDir
}

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

	outStore := driver.(store.OutgoingShareStore)

	// Create a share
	share := testutil.NewOutgoingShareFixture()
	if err := outStore.CreateOutgoingShare(ctx, share); err != nil {
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

	outStore2 := driver2.(store.OutgoingShareStore)
	got, err := outStore2.GetOutgoingShare(ctx, share.ProviderId)
	if err != nil {
		t.Fatalf("share not found after restart: %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("data corruption: expected %q, got %q", share.ProviderId, got.ProviderId)
	}
}
