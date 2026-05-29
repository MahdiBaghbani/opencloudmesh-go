// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestTokenExchangeDisabled tests that when token exchange is globally disabled,
// the endpoint returns 501 Not Implemented and discovery omits the capability.
func TestTokenExchangeDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "token-disabled",
		Mode:                  "dev",
		KeepSignatureDefaults: true,
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
		Name:                  "per-service-config",
		Mode:                  "dev",
		KeepSignatureDefaults: true,
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
		Name:                  "token-nested-path",
		Mode:                  "dev",
		KeepSignatureDefaults: true,
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
