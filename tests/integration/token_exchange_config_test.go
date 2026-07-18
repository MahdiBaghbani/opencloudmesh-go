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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	tsrouting "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/routing"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestTokenExchangeWithPerServiceConfig tests that the [http.services.*] TOML shape works.
// Verifies the per-service config model is functional end-to-end.
func TestTokenExchangeWithPerServiceConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)

	// Use per-service config instead of flat [token_exchange].
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "per-service-config",
		Mode:                  "dev",
		KeepSignatureDefaults: true,
		ExtraConfig: `
# Per-service configuration (Reva-aligned shape)
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
		opts := service.RouteOpts{
			TokenExchangePath: "auth/exchange",
		}
		tokenPath, ok := tsrouting.OCMTokenFullPath(opts)
		if !ok {
			t.Fatal("Routes(opts) missing token endpoint for auth/exchange")
		}
		if tokenPath != "/ocm/auth/exchange" {
			t.Fatalf("aggregate token path = %q, want /ocm/auth/exchange", tokenPath)
		}

		// POST to aggregate path should route to handler (not 404)
		data := url.Values{}
		data.Set("grant_type", "ocm_share")
		data.Set("client_id", "receiver.example.com")
		data.Set("code", "nonexistent-secret")

		resp, err := http.Post(
			srv.BaseURL+tokenPath,
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
		opts := service.RouteOpts{
			TokenExchangePath: "token/v2",
		}
		tokenPath, ok := tsrouting.OCMTokenFullPath(opts)
		if !ok {
			t.Fatal("Routes(opts) missing token endpoint for token/v2")
		}
		if tokenPath != "/ocm/token/v2" {
			t.Fatalf("aggregate token path = %q, want /ocm/token/v2", tokenPath)
		}

		// POST to aggregate path should route to handler (not 404)
		data := url.Values{}
		data.Set("grant_type", "ocm_share")
		data.Set("client_id", "receiver.example.com")
		data.Set("code", "nonexistent-secret")

		resp, err := http.Post(
			srv.BaseURL+tokenPath,
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
		defaultPath, ok := tsrouting.OCMTokenFullPath(service.DefaultRouteOpts())
		if !ok {
			t.Fatal("Routes(opts) missing default token endpoint")
		}

		// POST to default aggregate path should return 404 when custom path is configured
		data := url.Values{}
		data.Set("grant_type", "ocm_share")
		data.Set("client_id", "receiver.example.com")
		data.Set("code", "some-secret")

		resp, err := http.Post(
			srv.BaseURL+defaultPath,
			"application/x-www-form-urlencoded",
			strings.NewReader(data.Encode()),
		)
		if err != nil {
			t.Fatalf("failed to call default token endpoint: %v", err)
		}
		defer resp.Body.Close()

		// Should return 404 because the route is now at /ocm/token/v2
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("default path %q should return 404 when custom path is configured, got %d", defaultPath, resp.StatusCode)
		}
	})
}
