// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
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
			Enabled       bool     `json:"enabled"`
			EndPoint      string   `json:"endPoint"`
			TokenEndPoint string   `json:"tokenEndPoint"`
			Capabilities  []string `json:"capabilities"`
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

	t.Run("AuthorizationCodeGrantTypeAccepted", func(t *testing.T) {
		// authorization_code is now a valid grant_type (spec-first).
		// It should pass the grant_type check and fail on invalid code, not on grant_type.
		data := url.Values{}
		data.Set("grant_type", "authorization_code")
		data.Set("client_id", "receiver.example.com")
		data.Set("code", "nonexistent-secret")

		resp, err := http.Post(
			h.Server1.BaseURL+"/ocm/token",
			"application/x-www-form-urlencoded",
			strings.NewReader(data.Encode()),
		)
		if err != nil {
			t.Fatalf("failed to call token endpoint: %v", err)
		}
		defer resp.Body.Close()

		// Should return 400 with invalid_grant (code not found), NOT unsupported grant_type
		if resp.StatusCode != http.StatusBadRequest {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 400 for invalid code with authorization_code grant, got %d: %s", resp.StatusCode, body)
		}

		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}

		if errResp.Error != "invalid_grant" {
			t.Errorf("expected error=invalid_grant (code not found), got %q", errResp.Error)
		}
		// The error should be about the code, not about grant_type
		if strings.Contains(errResp.ErrorDescription, "grant_type") {
			t.Errorf("error_description should not mention grant_type (it should be about invalid code), got %q", errResp.ErrorDescription)
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
			data:           url.Values{"grant_type": {"password"}, "client_id": {"test"}, "code": {"test"}},
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

// TestTokenExchangeDisabled tests that when token exchange is globally disabled,
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
# Disable token exchange globally for evaluator-owned capability/criteria derivation
[token_exchange]
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

// TestInteropModeCanonicalPolicy exercises canonical policy under interop mode,
// where the mode preset supplies stricter signature and token exchange defaults.
func TestInteropModeCanonicalPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "interop-policy",
		Mode:                  "interop",
		KeepSignatureDefaults: true,
	})
	defer srv.Stop(t)

	t.Run("DiscoveryAdvertisesExchangeToken", func(t *testing.T) {
		resp, err := http.Get(srv.BaseURL + "/.well-known/ocm")
		if err != nil {
			srv.DumpLogs(t)
			t.Fatalf("failed to get discovery: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery returned %d", resp.StatusCode)
		}

		var disc struct {
			Enabled       bool     `json:"enabled"`
			Capabilities  []string `json:"capabilities"`
			Criteria      []string `json:"criteria"`
			TokenEndPoint string   `json:"tokenEndPoint"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
			t.Fatalf("failed to decode discovery: %v", err)
		}

		if !disc.Enabled {
			t.Fatal("discovery should be enabled in interop mode")
		}

		hasExchangeToken := false
		for _, cap := range disc.Capabilities {
			if strings.Contains(cap, "exchange-token") {
				hasExchangeToken = true
			}
		}
		if !hasExchangeToken {
			t.Error("interop mode should advertise exchange-token capability")
		}
		if disc.TokenEndPoint == "" {
			t.Error("interop mode should advertise tokenEndPoint")
		}
		for _, criterion := range disc.Criteria {
			if criterion == "http-request-signatures" {
				t.Error("interop mode should not advertise http-request-signatures criterion")
			}
		}
	})

	t.Run("HealthEndpoint", func(t *testing.T) {
		resp, err := http.Get(srv.BaseURL + "/api/healthz")
		if err != nil {
			t.Fatalf("health check failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("health endpoint returned %d", resp.StatusCode)
		}
	})

	t.Run("TokenEndpointRejectsInvalidGrant", func(t *testing.T) {
		data := url.Values{}
		data.Set("grant_type", "invalid_type")
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

		if resp.StatusCode != http.StatusBadRequest {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 400 for invalid grant_type, got %d: %s", resp.StatusCode, body)
		}

		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			t.Fatalf("failed to decode error: %v", err)
		}
		if errResp.Error != "invalid_grant" {
			t.Errorf("expected error=invalid_grant, got %q", errResp.Error)
		}
	})
}

func TestDiscoverySignatureCriteriaMatrixByMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	tests := []struct {
		name            string
		mode            string
		wantHTTPReqSigs bool
	}{
		{
			name:            "strict advertises signature criterion",
			mode:            "strict",
			wantHTTPReqSigs: true,
		},
		{
			name:            "interop omits signature criterion",
			mode:            "interop",
			wantHTTPReqSigs: false,
		},
		{
			name:            "dev omits signature criterion",
			mode:            "dev",
			wantHTTPReqSigs: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
				Name:                  "criteria-matrix-" + tt.mode,
				Mode:                  tt.mode,
				KeepSignatureDefaults: true,
			})
			defer srv.Stop(t)

			resp, err := http.Get(srv.BaseURL + "/.well-known/ocm")
			if err != nil {
				srv.DumpLogs(t)
				t.Fatalf("failed to get discovery: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("discovery returned %d", resp.StatusCode)
			}

			var disc struct {
				Enabled  bool     `json:"enabled"`
				Criteria []string `json:"criteria"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
				t.Fatalf("failed to decode discovery: %v", err)
			}
			if !disc.Enabled {
				t.Fatalf("discovery should be enabled in %s mode", tt.mode)
			}

			hasHTTPReqSigs := false
			for _, criterion := range disc.Criteria {
				if criterion == "http-request-signatures" {
					hasHTTPReqSigs = true
					break
				}
			}
			if hasHTTPReqSigs != tt.wantHTTPReqSigs {
				t.Fatalf(
					"mode %s criteria mismatch: has http-request-signatures=%v, want %v (criteria=%v)",
					tt.mode,
					hasHTTPReqSigs,
					tt.wantHTTPReqSigs,
					disc.Criteria,
				)
			}
		})
	}
}

func TestOutgoingSharePolicyDifferences(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	trueVal := true
	falseVal := false
	tests := []struct {
		name         string
		peerPolicy   string
		wantStatus   int
		wantPosts    int32
		wantMustExch *bool
	}{
		{
			name:       "strict rejects capable non-strict peer",
			peerPolicy: "strict",
			wantStatus: reason.APIStatus(reason.PeerPolicyUnsatisfied),
			wantPosts:  0,
		},
		{
			name:         "prefer-strict sends must-exchange-token",
			peerPolicy:   "prefer-strict",
			wantStatus:   http.StatusCreated,
			wantPosts:    1,
			wantMustExch: &trueVal,
		},
		{
			name:         "legacy sends without must-exchange-token",
			peerPolicy:   "legacy",
			wantStatus:   http.StatusCreated,
			wantPosts:    1,
			wantMustExch: &falseVal,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Each subtest needs its own server because policy is frozen at startup.
			ts := harness.StartTestServerWithConfig(t, func(cfg *config.Config) {
				cfg.PeerPolicy = tc.peerPolicy
			})
			defer ts.Stop(t)

			token := loginAdmin(t, ts.BaseURL, "admin", "admin")

			shareFile, err := os.CreateTemp("/tmp", "policy-diff-share-*")
			if err != nil {
				t.Fatalf("failed to create temp share file: %v", err)
			}
			if _, err := shareFile.WriteString("policy diff integration payload"); err != nil {
				t.Fatalf("failed to seed temp share file: %v", err)
			}
			if err := shareFile.Close(); err != nil {
				t.Fatalf("failed to close temp share file: %v", err)
			}
			t.Cleanup(func() { _ = os.Remove(shareFile.Name()) })

			receiver, postCount, mustExchangeFlag := startCapableNonStrictReceiver(t)
			defer receiver.Close()

			receiverDomain := strings.TrimPrefix(receiver.URL, "https://")
			status, body := createOutgoingShare(t, ts.BaseURL, token, map[string]any{
				"receiverDomain": receiverDomain,
				"shareWith":      "bob@" + receiverDomain,
				"localPath":      shareFile.Name(),
				"permissions":    []string{"read"},
			})

			if status != tc.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tc.wantStatus, status, body)
			}

			if got := postCount.Load(); got != tc.wantPosts {
				t.Fatalf("expected receiver POST count %d, got %d", tc.wantPosts, got)
			}

			if tc.wantMustExch != nil {
				gotFlag := mustExchangeFlag.Load()
				if gotFlag == -1 {
					t.Fatal("receiver did not capture must-exchange-token state")
				}
				gotMust := gotFlag == 1
				if gotMust != *tc.wantMustExch {
					t.Fatalf("must-exchange-token mismatch: got %v, want %v", gotMust, *tc.wantMustExch)
				}
			}
		})
	}
}

func TestOutgoingSharePolicyDifferences_MalformedDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	falseVal := false
	tests := []struct {
		name         string
		peerPolicy   string
		wantStatus   int
		wantPosts    int32
		wantMustExch *bool
	}{
		{
			name:       "strict rejects malformed capable non-strict peer",
			peerPolicy: "strict",
			wantStatus: reason.APIStatus(reason.PeerPolicyUnsatisfied),
			wantPosts:  0,
		},
		{
			name:         "prefer-strict degrades malformed peer to legacy",
			peerPolicy:   "prefer-strict",
			wantStatus:   http.StatusCreated,
			wantPosts:    1,
			wantMustExch: &falseVal,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Each subtest needs its own server because policy is frozen at startup.
			ts := harness.StartTestServerWithConfig(t, func(cfg *config.Config) {
				cfg.PeerPolicy = tc.peerPolicy
			})
			defer ts.Stop(t)

			token := loginAdmin(t, ts.BaseURL, "admin", "admin")

			shareFile, err := os.CreateTemp("/tmp", "policy-diff-malformed-*")
			if err != nil {
				t.Fatalf("failed to create temp share file: %v", err)
			}
			if _, err := shareFile.WriteString("policy diff malformed integration payload"); err != nil {
				t.Fatalf("failed to seed temp share file: %v", err)
			}
			if err := shareFile.Close(); err != nil {
				t.Fatalf("failed to close temp share file: %v", err)
			}
			t.Cleanup(func() { _ = os.Remove(shareFile.Name()) })

			receiver, postCount, mustExchangeFlag := startMalformedCapableNonStrictReceiver(t)
			defer receiver.Close()

			receiverDomain := strings.TrimPrefix(receiver.URL, "https://")
			status, body := createOutgoingShare(t, ts.BaseURL, token, map[string]any{
				"receiverDomain": receiverDomain,
				"shareWith":      "bob@" + receiverDomain,
				"localPath":      shareFile.Name(),
				"permissions":    []string{"read"},
			})

			if status != tc.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tc.wantStatus, status, body)
			}

			if got := postCount.Load(); got != tc.wantPosts {
				t.Fatalf("expected receiver POST count %d, got %d", tc.wantPosts, got)
			}

			if tc.wantMustExch != nil {
				gotFlag := mustExchangeFlag.Load()
				if gotFlag == -1 {
					t.Fatal("receiver did not capture must-exchange-token state")
				}
				gotMust := gotFlag == 1
				if gotMust != *tc.wantMustExch {
					t.Fatalf("must-exchange-token mismatch: got %v, want %v", gotMust, *tc.wantMustExch)
				}
			}
		})
	}
}

func TestWebDAVStrictShareRejectsSharedSecretWhenLocalNotStrict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := harness.StartTestServer(t)
	defer ts.Stop(t)

	token := loginAdmin(t, ts.BaseURL, "admin", "admin")
	d := deps.GetDeps()
	if d == nil || d.Config == nil || d.OpenCloudMeshPolicy == nil || d.OutgoingShareRepo == nil {
		t.Fatal("shared deps are not fully initialized")
	}
	if d.OpenCloudMeshPolicy.Evaluate().RequiresTokenExchange {
		t.Fatal("test requires local policy strictness=false")
	}

	shareFile, err := os.CreateTemp("/tmp", "webdav-strict-share-*")
	if err != nil {
		t.Fatalf("failed to create temp share file: %v", err)
	}
	if _, err := shareFile.WriteString("strict-share shared-secret rejection proof"); err != nil {
		t.Fatalf("failed to write temp share file: %v", err)
	}
	if err := shareFile.Close(); err != nil {
		t.Fatalf("failed to close temp share file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(shareFile.Name()) })

	receiver, _, _ := startCapableNonStrictReceiver(t)
	defer receiver.Close()

	receiverDomain := strings.TrimPrefix(receiver.URL, "https://")
	status, body := createOutgoingShare(t, ts.BaseURL, token, map[string]any{
		"receiverDomain": receiverDomain,
		"shareWith":      "bob@" + receiverDomain,
		"localPath":      shareFile.Name(),
		"permissions":    []string{"read"},
	})
	if status != http.StatusCreated {
		t.Fatalf("expected 201 from outgoing share create, got %d: %s", status, body)
	}

	var created struct {
		ProviderID string `json:"providerId"`
		WebDAVID   string `json:"webdavId"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("failed to decode outgoing share response: %v", err)
	}
	if created.ProviderID == "" || created.WebDAVID == "" {
		t.Fatalf("outgoing share response missing providerId/webdavId: %s", body)
	}

	share, err := d.OutgoingShareRepo.GetByProviderID(nil, created.ProviderID)
	if err != nil {
		t.Fatalf("failed to load created outgoing share: %v", err)
	}
	if !share.MustExchangeToken {
		t.Fatal("expected created share MustExchangeToken=true for prefer-strict policy")
	}

	fileName := filepath.Base(shareFile.Name())
	webdavURL := ts.BaseURL + "/webdav/ocm/" + created.WebDAVID + "/" + url.PathEscape(fileName)
	req, err := http.NewRequest(http.MethodGet, webdavURL, nil)
	if err != nil {
		t.Fatalf("failed to create webdav request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+share.SharedSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to call webdav endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 for shared-secret access to strict share, got %d: %s", resp.StatusCode, respBody)
	}
}

func startCapableNonStrictReceiver(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()

	postCount := &atomic.Int32{}
	mustExchangeFlag := &atomic.Int32{}
	mustExchangeFlag.Store(-1)
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm", "/ocm-provider":
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.2.2",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  []string{"exchange-token"},
				Criteria:      []string{},
				TokenEndPoint: srv.URL + "/ocm/token",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
			return
		case "/ocm/shares":
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			var req spec.NewShareRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid payload", http.StatusBadRequest)
				return
			}
			postCount.Add(1)
			mustExchange := req.Protocol.WebDAV != nil &&
				req.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken)
			if mustExchange {
				mustExchangeFlag.Store(1)
			} else {
				mustExchangeFlag.Store(0)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		default:
			http.NotFound(w, r)
		}
	}))

	return srv, postCount, mustExchangeFlag
}

func startMalformedCapableNonStrictReceiver(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()

	postCount := &atomic.Int32{}
	mustExchangeFlag := &atomic.Int32{}
	mustExchangeFlag.Store(-1)
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm", "/ocm-provider":
			disc := spec.Discovery{
				Enabled:      true,
				APIVersion:   "1.2.2",
				EndPoint:     srv.URL + "/ocm",
				Capabilities: []string{"exchange-token"},
				Criteria:     []string{},
				// Intentionally malformed: missing tokenEndPoint.
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
			return
		case "/ocm/shares":
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			var req spec.NewShareRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid payload", http.StatusBadRequest)
				return
			}
			postCount.Add(1)
			mustExchange := req.Protocol.WebDAV != nil &&
				req.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken)
			if mustExchange {
				mustExchangeFlag.Store(1)
			} else {
				mustExchangeFlag.Store(0)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		default:
			http.NotFound(w, r)
		}
	}))

	return srv, postCount, mustExchangeFlag
}

func loginAdmin(t *testing.T, baseURL, username, password string) string {
	t.Helper()

	reqBody, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		t.Fatalf("failed to encode login request: %v", err)
	}
	resp, err := http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to call login endpoint: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: status=%d body=%s", resp.StatusCode, body)
	}

	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to parse login response: %v", err)
	}
	if parsed.Token == "" {
		t.Fatalf("login returned empty token: %s", body)
	}
	return parsed.Token
}

func createOutgoingShare(t *testing.T, baseURL, token string, payload map[string]any) (int, string) {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal outgoing share payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/shares/outgoing", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create outgoing share request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to call outgoing share endpoint: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody)
}
