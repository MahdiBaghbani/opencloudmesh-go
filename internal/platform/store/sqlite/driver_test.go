package sqlite_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlite"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

func TestSQLiteDriver(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-sqlite-*")

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
