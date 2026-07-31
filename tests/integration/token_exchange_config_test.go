// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
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
		Name: "per-service-config",
		Mode: "dev",
		ExtraConfig: `
# Per-service configuration (Reva-aligned shape)
[http.services.wellknown]
[http.services.wellknown.ocmprovider]
provider = "TestProvider"

[http.services.wellknown.ocmprovider.token_exchange]
path = "auth/exchange"

[http.services.ocm]
[http.services.ocm.token_exchange]
path = "auth/exchange"
`,
	})
	defer srv.Stop(t)

	t.Run("DiscoveryShowsCustomProvider", func(t *testing.T) {
		disc := getDiscoveryTokenInfo(t, srv.BaseURL)

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
		tokenPath := requireTokenPath(t, service.RouteOpts{TokenExchangePath: "auth/exchange"}, "/ocm/auth/exchange")

		// POST to aggregate path should route to handler (not 404)
		status, body := postTokenGrantForm(t, srv.BaseURL, tokenPath, "nonexistent-secret")
		assertTokenRouteHandled(t, status, body, tokenPath)
	})
}

// discoveryTokenInfo carries the discovery fields relevant to token exchange config.
type discoveryTokenInfo struct {
	Provider      string `json:"provider"`
	TokenEndPoint string `json:"tokenEndPoint"`
}

// getDiscoveryTokenInfo fetches the well-known discovery document and decodes
// the token exchange fields.
func getDiscoveryTokenInfo(t *testing.T, baseURL string) discoveryTokenInfo {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+"/.well-known/ocm", nil)
	if err != nil {
		t.Fatalf("build discovery request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("failed to get discovery: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery returned %d", resp.StatusCode)
	}

	var disc discoveryTokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatalf("failed to decode discovery: %v", err)
	}

	return disc
}

// requireTokenPath resolves the aggregate token path for opts and checks it
// matches the configured expectation.
func requireTokenPath(t *testing.T, opts service.RouteOpts, wantPath string) string {
	t.Helper()

	tokenPath, ok := tsrouting.OCMTokenFullPath(opts)
	if !ok {
		t.Fatalf("Routes(opts) missing token endpoint for %s", wantPath)
	}

	if tokenPath != wantPath {
		t.Fatalf("aggregate token path = %q, want %s", tokenPath, wantPath)
	}

	return tokenPath
}

// postTokenGrantForm POSTs an authorization_code grant form to the token path
// and returns the status code and response body.
func postTokenGrantForm(t *testing.T, baseURL, tokenPath, code string) (int, []byte) {
	t.Helper()

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", "receiver.example.com")
	data.Set("code", code)

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		baseURL+tokenPath,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("failed to call token endpoint: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	return resp.StatusCode, body
}

// assertTokenRouteHandled checks the token path routed to a handler (400
// invalid_grant for a nonexistent code, never 404).
func assertTokenRouteHandled(t *testing.T, status int, body []byte, tokenPath string) {
	t.Helper()

	if status == http.StatusNotFound {
		t.Fatalf("path %s returned 404 - route not mounted correctly", tokenPath)
	}

	if status != http.StatusBadRequest {
		t.Logf("path %s returned %d (expected 400): %s", tokenPath, status, body)
	}
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
path = "token/v2"

[http.services.ocm.token_exchange]
path = "token/v2"
`,
	})
	defer srv.Stop(t)

	t.Run("DiscoveryAdvertisesNestedPath", func(t *testing.T) {
		disc := getDiscoveryTokenInfo(t, srv.BaseURL)

		// tokenEndPoint should end with /ocm/token/v2
		if !strings.HasSuffix(disc.TokenEndPoint, "/ocm/token/v2") {
			t.Errorf("tokenEndPoint should end with /ocm/token/v2, got %q", disc.TokenEndPoint)
		}
	})

	t.Run("NestedPathRoutesToHandler", func(t *testing.T) {
		tokenPath := requireTokenPath(t, service.RouteOpts{TokenExchangePath: "token/v2"}, "/ocm/token/v2")

		// POST to aggregate path should route to handler (not 404)
		status, body := postTokenGrantForm(t, srv.BaseURL, tokenPath, "nonexistent-secret")
		assertTokenRouteHandled(t, status, body, tokenPath)
	})

	t.Run("DefaultPathReturns404", func(t *testing.T) {
		defaultPath, ok := tsrouting.OCMTokenFullPath(service.DefaultRouteOpts())
		if !ok {
			t.Fatal("Routes(opts) missing default token endpoint")
		}

		// POST to default aggregate path should return 404 when custom path is configured
		status, _ := postTokenGrantForm(t, srv.BaseURL, defaultPath, "some-secret")

		// Should return 404 because the route is now at /ocm/token/v2
		if status != http.StatusNotFound {
			t.Errorf("default path %q should return 404 when custom path is configured, got %d", defaultPath, status)
		}
	})
}
