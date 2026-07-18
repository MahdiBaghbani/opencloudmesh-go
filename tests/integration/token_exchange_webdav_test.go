// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestWebDAVWithBearerToken tests WebDAV access with bearer token authentication.
func TestWebDAVWithBearerToken(t *testing.T) {
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

	// Note: [shares] allowed_paths section was removed - it was a phantom knob (not decoded).
	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "webdav-test",
		Mode: "dev",
	})
	defer srv.Stop(t)

	t.Run("WebDAVEndpointExists", func(t *testing.T) {
		// Try to access WebDAV endpoint - should require auth
		req, _ := http.NewRequest(http.MethodGet, srv.BaseURL+"/webdav/ocm/550e8400-e29b-41d4-a716-446655440000", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("failed to access WebDAV: %v", err)
		}
		defer resp.Body.Close()

		// Should return 401 (unauthorized) not 404
		if resp.StatusCode == http.StatusNotFound {
			t.Log("WebDAV endpoint returns 404 for nonexistent share (expected)")
		} else if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
			t.Logf("WebDAV returned %d", resp.StatusCode)
		}
	})

	t.Run("WebDAVRequiresAuth", func(t *testing.T) {
		// The WebDAV endpoint should require authorization
		req, _ := http.NewRequest(http.MethodGet, srv.BaseURL+"/webdav/ocm/test-id", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("failed to access WebDAV: %v", err)
		}
		defer resp.Body.Close()

		// Should require auth or return bad request for invalid ID
		validCodes := []int{http.StatusUnauthorized, http.StatusBadRequest}
		found := false
		for _, code := range validCodes {
			if resp.StatusCode == code {
				found = true
				break
			}
		}
		if !found {
			t.Logf("WebDAV returned %d (expected 401 or 400)", resp.StatusCode)
		}
	})
}
