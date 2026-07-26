package mirror_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/mirror"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

func TestMirrorDriver(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-mirror-*")

	cfg := &store.DriverConfig{
		Driver:  "mirror",
		DataDir: tempDir,
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
