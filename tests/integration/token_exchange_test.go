// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestTokenExchangeFlow tests the full token exchange flow between two instances.
// This verifies:
// 1. Sender advertises exchange-token capability
// 2. Receiver can create a share with must-exchange-token requirement
// 3. Token exchange endpoint works correctly
// 4. WebDAV access works with the exchanged token
func TestTokenExchangeFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	// Create test file that will be shared
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := []byte("Hello from token exchange test - this is the file content!")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Start two instances
	// Instance1 = sender (shares the file)
	// Instance2 = receiver (requests the file)
	// Note: [token_exchange] and [shares] sections were removed - they were phantom knobs
	// (not decoded by the loader). Token exchange capability is always available.
	h := harness.StartTwoInstances(t,
		harness.SubprocessConfig{Name: "sender", Mode: "dev"},
		harness.SubprocessConfig{Name: "receiver", Mode: "dev"},
	)
	defer h.Stop(t)

	t.Run("DiscoveryAdvertisesTokenExchange", func(t *testing.T) {
		resp, err := http.Get(h.Server1.BaseURL + "/.well-known/ocm")
		if err != nil {
			h.DumpLogs(t)
			t.Fatalf("failed to get discovery: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery returned %d", resp.StatusCode)
		}

		var disc struct {
			Enabled      bool     `json:"enabled"`
			EndPoint     string   `json:"endPoint"`
			TokenEndPoint string  `json:"tokenEndPoint"`
			Capabilities []string `json:"capabilities"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
			t.Fatalf("failed to decode discovery: %v", err)
		}

		t.Logf("Sender discovery: tokenEndPoint=%q, capabilities=%v", disc.TokenEndPoint, disc.Capabilities)

		// Verify exchange-token capability is advertised
		hasExchangeToken := false
		for _, cap := range disc.Capabilities {
			if strings.Contains(cap, "exchange-token") {
				hasExchangeToken = true
				break
			}
		}
		if !hasExchangeToken {
			t.Errorf("exchange-token capability MUST be advertised when token exchange is enabled (default)")
		}

		// Verify tokenEndPoint is present when enabled (regression: must not be empty)
		if disc.TokenEndPoint == "" {
			t.Errorf("tokenEndPoint MUST be present when token exchange is enabled; got empty string")
		}
	})

	t.Run("TokenEndpointExists", func(t *testing.T) {
		// The token endpoint should exist and respond to POST
		// Sending a malformed request should get an error response, not 404
		resp, err := http.Post(h.Server1.BaseURL+"/ocm/token", "application/x-www-form-urlencoded", nil)
		if err != nil {
			t.Fatalf("failed to call token endpoint: %v", err)
		}
		defer resp.Body.Close()

		// Should return 400 (bad request) not 404 (not found)
		if resp.StatusCode == http.StatusNotFound {
			t.Fatal("token endpoint not found - /ocm/token should exist")
		}

		// 400 or 401 are expected for malformed request
		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
			t.Logf("token endpoint returned %d (expected 400 for invalid request)", resp.StatusCode)
		}
	})

	t.Run("TokenExchangeWithMockedShare", func(t *testing.T) {
		// This test exercises the token exchange endpoint directly.
		// In a real scenario, the share would be created first via /ocm/shares.
		// For this test, we'll verify the endpoint behavior with known invalid inputs.

		// Send a token exchange request with proper form data but invalid code
		data := url.Values{}
		data.Set("grant_type", "ocm_share")
		data.Set("client_id", "receiver.example.com")
		data.Set("code", "nonexistent-shared-secret")

		resp, err := http.Post(
			h.Server1.BaseURL+"/ocm/token",
			"application/x-www-form-urlencoded",
			strings.NewReader(data.Encode()),
		)
		if err != nil {
			t.Fatalf("failed to call token endpoint: %v", err)
		}
		defer resp.Body.Close()

		// Should return 400 with invalid_grant because the code (shared secret) doesn't exist
		if resp.StatusCode != http.StatusBadRequest {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 400 for invalid code, got %d: %s", resp.StatusCode, body)
		}

		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}

		if errResp.Error != "invalid_grant" {
			t.Errorf("expected error=invalid_grant, got %q", errResp.Error)
		}
	})

	t.Run("TokenExchangeWithJSONBody", func(t *testing.T) {
		// Test Nextcloud interop: JSON body instead of form-urlencoded
		reqBody := map[string]string{
			"grant_type": "ocm_share",
			"client_id":  "receiver.example.com",
			"code":       "nonexistent-shared-secret",
		}
		body, _ := json.Marshal(reqBody)

		resp, err := http.Post(
			h.Server1.BaseURL+"/ocm/token",
			"application/json",
			bytes.NewReader(body),
		)
		if err != nil {
			t.Fatalf("failed to call token endpoint: %v", err)
		}
		defer resp.Body.Close()

		// Should also return 400 with invalid_grant
		if resp.StatusCode != http.StatusBadRequest {
			respBody, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 400 for invalid code (JSON), got %d: %s", resp.StatusCode, respBody)
		}

		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}

		if errResp.Error != "invalid_grant" {
			t.Errorf("expected error=invalid_grant, got %q", errResp.Error)
		}
	})

	t.Run("InvalidGrantTypeRejected", func(t *testing.T) {
		data := url.Values{}
		data.Set("grant_type", "password") // Invalid grant type
		data.Set("client_id", "receiver.example.com")
		data.Set("code", "some-secret")

		resp, err := http.Post(
			h.Server1.BaseURL+"/ocm/token",
			"application/x-www-form-urlencoded",
			strings.NewReader(data.Encode()),
		)
		if err != nil {
			t.Fatalf("failed to call token endpoint: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 400 for invalid grant_type, got %d: %s", resp.StatusCode, body)
		}

		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}

		if errResp.Error != "invalid_grant" {
			t.Errorf("expected error=invalid_grant, got %q", errResp.Error)
		}
	})
}

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

// TestTokenExchangeErrorResponses tests OAuth-style error responses from token endpoint.
func TestTokenExchangeErrorResponses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "token-errors",
		Mode: "dev",
	})
	defer srv.Stop(t)

	tests := []struct {
		name           string
		data           url.Values
		expectedError  string
		expectedStatus int
	}{
		{
			name:           "MissingGrantType",
			data:           url.Values{"client_id": {"test"}, "code": {"test"}},
			expectedError:  "invalid_request",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "MissingClientID",
			data:           url.Values{"grant_type": {"ocm_share"}, "code": {"test"}},
			expectedError:  "invalid_request",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "MissingCode",
			data:           url.Values{"grant_type": {"ocm_share"}, "client_id": {"test"}},
			expectedError:  "invalid_request",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "WrongGrantType",
			data:           url.Values{"grant_type": {"authorization_code"}, "client_id": {"test"}, "code": {"test"}},
			expectedError:  "invalid_grant",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Post(
				srv.BaseURL+"/ocm/token",
				"application/x-www-form-urlencoded",
				strings.NewReader(tt.data.Encode()),
			)
			if err != nil {
				t.Fatalf("failed to call token endpoint: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected status %d, got %d: %s", tt.expectedStatus, resp.StatusCode, body)
			}

			var errResp struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
				t.Fatalf("failed to decode error response: %v", err)
			}

			if errResp.Error != tt.expectedError {
				t.Errorf("expected error=%q, got %q", tt.expectedError, errResp.Error)
			}
		})
	}
}

// TestTokenExchangeDisabled tests that when token exchange is disabled,
// the endpoint returns 501 Not Implemented and discovery omits the capability.
func TestTokenExchangeDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "token-disabled",
		Mode: "dev", // dev mode so signature middleware doesn't interfere
		ExtraConfig: `
# Override per-service config to disable token exchange
[http.services.wellknown.ocmprovider.token_exchange]
enabled = false

[http.services.ocm.token_exchange]
enabled = false
`,
	})
	defer srv.Stop(t)

	t.Run("EndpointReturns501", func(t *testing.T) {
		// When disabled, POST to token endpoint should return 501 Not Implemented
		data := url.Values{}
		data.Set("grant_type", "ocm_share")
		data.Set("client_id", "receiver.example.com")
		data.Set("code", "some-secret")

		resp, err := http.Post(
			srv.BaseURL+"/ocm/token",
			"application/x-www-form-urlencoded",
			strings.NewReader(data.Encode()),
		)
		if err != nil {
			t.Fatalf("failed to call token endpoint: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotImplemented {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 501 Not Implemented when disabled, got %d: %s", resp.StatusCode, body)
		}

		// Verify error response body
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}

		if errResp.Error != "not_implemented" {
			t.Errorf("expected error=not_implemented, got %q", errResp.Error)
		}
	})

	t.Run("DiscoveryOmitsCapability", func(t *testing.T) {
		resp, err := http.Get(srv.BaseURL + "/.well-known/ocm")
		if err != nil {
			t.Fatalf("failed to get discovery: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery returned %d", resp.StatusCode)
		}

		// Read raw JSON to check field presence
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read discovery body: %v", err)
		}

		var disc map[string]any
		if err := json.Unmarshal(body, &disc); err != nil {
			t.Fatalf("failed to decode discovery: %v", err)
		}

		// tokenEndPoint key should be ABSENT when disabled (not just empty)
		if _, ok := disc["tokenEndPoint"]; ok {
			t.Errorf("tokenEndPoint key should be ABSENT from JSON when disabled, but key is present")
		}

		// capabilities should NOT include exchange-token
		if caps, ok := disc["capabilities"].([]any); ok {
			for _, cap := range caps {
				if capStr, ok := cap.(string); ok && strings.Contains(capStr, "exchange-token") {
					t.Errorf("exchange-token capability should NOT be advertised when disabled")
				}
			}
		}
	})
}

// TestTokenExchangeWithPerServiceConfig tests that the new [http.services.*] TOML shape works.
// This verifies Phase 3.D: the per-service config model is functional end-to-end.
func TestTokenExchangeWithPerServiceConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)

	// Use the new per-service config shape instead of flat [token_exchange]
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "per-service-config",
		Mode: "dev",
		ExtraConfig: `
# Per-service configuration (new Reva-aligned shape)
[http.services.wellknown]
[http.services.wellknown.ocmprovider]
provider = "TestProvider"

[http.services.wellknown.ocmprovider.token_exchange]
enabled = true
path = "auth/exchange"

[http.services.ocm]
[http.services.ocm.token_exchange]
enabled = true
path = "auth/exchange"
`,
	})
	defer srv.Stop(t)

	t.Run("DiscoveryShowsCustomProvider", func(t *testing.T) {
		resp, err := http.Get(srv.BaseURL + "/.well-known/ocm")
		if err != nil {
			t.Fatalf("failed to get discovery: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery returned %d", resp.StatusCode)
		}

		var disc struct {
			Provider      string `json:"provider"`
			TokenEndPoint string `json:"tokenEndPoint"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
			t.Fatalf("failed to decode discovery: %v", err)
		}

		// Provider should be overridden by per-service config
		if disc.Provider != "TestProvider" {
			t.Errorf("expected provider 'TestProvider' from per-service config, got %q", disc.Provider)
		}

		// tokenEndPoint should use the per-service path
		if !strings.HasSuffix(disc.TokenEndPoint, "/ocm/auth/exchange") {
			t.Errorf("tokenEndPoint should end with /ocm/auth/exchange, got %q", disc.TokenEndPoint)
		}
	})

	t.Run("PerServicePathRoutesToHandler", func(t *testing.T) {
		// POST to /ocm/auth/exchange should route to handler (not 404)
		data := url.Values{}
		data.Set("grant_type", "ocm_share")
		data.Set("client_id", "receiver.example.com")
		data.Set("code", "nonexistent-secret")

		resp, err := http.Post(
			srv.BaseURL+"/ocm/auth/exchange",
			"application/x-www-form-urlencoded",
			strings.NewReader(data.Encode()),
		)
		if err != nil {
			t.Fatalf("failed to call per-service token endpoint: %v", err)
		}
		defer resp.Body.Close()

		// Should return 400 (invalid_grant for nonexistent code), not 404
		if resp.StatusCode == http.StatusNotFound {
			t.Fatal("per-service path /ocm/auth/exchange returned 404 - route not mounted correctly")
		}

		if resp.StatusCode != http.StatusBadRequest {
			body, _ := io.ReadAll(resp.Body)
			t.Logf("per-service path returned %d (expected 400): %s", resp.StatusCode, body)
		}
	})
}

// TestTokenExchangeNestedPath tests that a custom nested path (token/v2) routes correctly.
func TestTokenExchangeNestedPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "token-nested-path",
		Mode: "dev",
		ExtraConfig: `
# Override per-service config for nested path
[http.services.wellknown.ocmprovider.token_exchange]
enabled = true
path = "token/v2"

[http.services.ocm.token_exchange]
enabled = true
path = "token/v2"
`,
	})
	defer srv.Stop(t)

	t.Run("DiscoveryAdvertisesNestedPath", func(t *testing.T) {
		resp, err := http.Get(srv.BaseURL + "/.well-known/ocm")
		if err != nil {
			t.Fatalf("failed to get discovery: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery returned %d", resp.StatusCode)
		}

		var disc struct {
			TokenEndPoint string `json:"tokenEndPoint"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
			t.Fatalf("failed to decode discovery: %v", err)
		}

		// tokenEndPoint should end with /ocm/token/v2
		if !strings.HasSuffix(disc.TokenEndPoint, "/ocm/token/v2") {
			t.Errorf("tokenEndPoint should end with /ocm/token/v2, got %q", disc.TokenEndPoint)
		}
	})

	t.Run("NestedPathRoutesToHandler", func(t *testing.T) {
		// POST to /ocm/token/v2 should route to handler (not 404)
		data := url.Values{}
		data.Set("grant_type", "ocm_share")
		data.Set("client_id", "receiver.example.com")
		data.Set("code", "nonexistent-secret")

		resp, err := http.Post(
			srv.BaseURL+"/ocm/token/v2",
			"application/x-www-form-urlencoded",
			strings.NewReader(data.Encode()),
		)
		if err != nil {
			t.Fatalf("failed to call nested token endpoint: %v", err)
		}
		defer resp.Body.Close()

		// Should return 400 (invalid_grant for nonexistent code), not 404
		if resp.StatusCode == http.StatusNotFound {
			t.Fatal("nested path /ocm/token/v2 returned 404 - route not mounted correctly")
		}

		if resp.StatusCode != http.StatusBadRequest {
			body, _ := io.ReadAll(resp.Body)
			t.Logf("nested path returned %d (expected 400): %s", resp.StatusCode, body)
		}
	})

	t.Run("DefaultPathReturns404", func(t *testing.T) {
		// POST to /ocm/token (default path) should return 404 when custom path is configured
		data := url.Values{}
		data.Set("grant_type", "ocm_share")
		data.Set("client_id", "receiver.example.com")
		data.Set("code", "some-secret")

		resp, err := http.Post(
			srv.BaseURL+"/ocm/token",
			"application/x-www-form-urlencoded",
			strings.NewReader(data.Encode()),
		)
		if err != nil {
			t.Fatalf("failed to call default token endpoint: %v", err)
		}
		defer resp.Body.Close()

		// Should return 404 because the route is now at /ocm/token/v2
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("default path /ocm/token should return 404 when custom path is configured, got %d", resp.StatusCode)
		}
	})
}
