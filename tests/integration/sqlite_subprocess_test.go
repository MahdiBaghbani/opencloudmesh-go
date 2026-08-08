// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestSubprocessSQLiteBackendBoots is the CGO_ENABLED=0 smoke test for the
// pure-Go sqlite driver: harness.BuildBinary always builds the subprocess
// with CGO_ENABLED=0, so booting with the sqlite backend proves the driver
// needs no cgo. Store init runs at boot, so a successful readiness probe plus
// the on-disk ocm.db confirms the backend works end to end. The harness pins
// the memory backend in generated configs, so this test declares its own
// [persistence] table.
func TestSubprocessSQLiteBackendBoots(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)

	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "sqlite-smoke",
		Mode: "dev",
		// The subprocess working directory is its temp dir, so the relative
		// data dir lands inside it.
		ExtraConfig: `
[persistence]
backend = "sqlite"
data_dir = "data"
`,
	})
	defer srv.Stop(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.BaseURL+"/api/healthz", nil)
	if err != nil {
		t.Fatalf("build healthz request: %v", err)
	}

	resp, err := srv.Client().Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("health check against sqlite-backed server failed: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected healthz 200 from sqlite-backed server, got %d", resp.StatusCode)
	}

	if _, err := os.Stat(filepath.Join(srv.TempDir, "data", "ocm.db")); err != nil {
		t.Fatalf("ocm.db not created by sqlite backend under CGO_ENABLED=0: %v", err)
	}
}
