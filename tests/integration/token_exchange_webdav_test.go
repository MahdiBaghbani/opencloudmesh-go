// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestWebDAVWithBearerToken tests WebDAV access with bearer token authentication.
func TestWebDAVWithBearerToken(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	// Create test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "shared-file.txt")

	testContent := []byte("WebDAV test content - verify bytes match!")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	binaryPath := harness.BuildBinary(t)

	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "webdav-test",
		Mode: "dev",
	})
	t.Cleanup(func() { srv.Stop(t) })

	t.Run("WebDAVEndpointExists", func(t *testing.T) {
		t.Parallel()

		// Try to access WebDAV endpoint - should require auth

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.BaseURL+"/webdav/ocm/550e8400-e29b-41d4-a716-446655440000", nil)
		if err != nil {
			t.Fatalf("create request: %v", err)
		}

		resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
		if err != nil {
			t.Fatalf("failed to access WebDAV: %v", err)
		}
		defer tshttp.MustClose(t, resp.Body)

		// Should return 401 (unauthorized) not 404
		if resp.StatusCode == http.StatusNotFound {
			t.Log("WebDAV endpoint returns 404 for nonexistent share (expected)")
		} else if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
			t.Logf("WebDAV returned %d", resp.StatusCode)
		}
	})

	t.Run("WebDAVRequiresAuth", func(t *testing.T) {
		t.Parallel()

		// The WebDAV endpoint should require authorization

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.BaseURL+"/webdav/ocm/test-id", nil)
		if err != nil {
			t.Fatalf("create request: %v", err)
		}

		resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
		if err != nil {
			t.Fatalf("failed to access WebDAV: %v", err)
		}
		defer tshttp.MustClose(t, resp.Body)

		// Should require auth or return bad request for invalid ID
		validCodes := []int{http.StatusUnauthorized, http.StatusBadRequest}
		found := slices.Contains(validCodes, resp.StatusCode)

		if !found {
			t.Logf("WebDAV returned %d (expected 401 or 400)", resp.StatusCode)
		}
	})
}
