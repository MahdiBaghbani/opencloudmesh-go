package json_test

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/json"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

func newJSONDriver(t *testing.T) (store.Driver, string) {
	t.Helper()
	tempDir := testutil.TempDataDir(t, "ocm-test-json-*")
	cfg := &store.DriverConfig{Driver: "json", DataDir: tempDir}
	d := testutil.OpenDriver(t, cfg)

	return d, tempDir
}

func TestJSONDriver(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-json-*")

	cfg := &store.DriverConfig{
		Driver:  "json",
		DataDir: tempDir,
	}

	testutil.RunDriverTests(t, "json", cfg)
}

func TestJSONDriverAtomicWrite(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-json-atomic-*")

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "json",
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

	// Reload driver - data should survive
	driver2 := testutil.OpenDriver(t, cfg)
	defer driver2.Close() //nolint:errcheck // test cleanup: driver close

	outStore2 := requireOutgoingShareStore(t, driver2)

	got, err := outStore2.GetOutgoingShare(ctx, share.ProviderId)
	if err != nil {
		t.Fatalf("share not found after restart: %v", err)
	}

	if got.ProviderId != share.ProviderId {
		t.Errorf("data corruption: expected %q, got %q", share.ProviderId, got.ProviderId)
	}
}
