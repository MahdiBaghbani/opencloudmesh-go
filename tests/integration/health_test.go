package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func TestHealthEndpoint(t *testing.T) {
	ts := harness.StartTestServer(t)
	defer ts.Stop(t)

	resp, err := http.Get(ts.BaseURL + "/api/healthz")
	if err != nil {
		t.Fatalf("failed to get health endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var health struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if health.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", health.Status)
	}
}

// TestHealthEndpointWithExternalBasePath guards against a harness readiness
// regression: when external_base_path is set, app endpoints (including
// /api/healthz) mount under that prefix, so in-process startup must not
// falsely fail by probing the bare root /api/healthz.
func TestHealthEndpointWithExternalBasePath(t *testing.T) {
	ts := harness.StartTestServerWithConfig(t, func(cfg *config.Config) {
		cfg.ExternalBasePath = "/ocm"
	})
	defer ts.Stop(t)

	resp, err := http.Get(ts.BaseURL + "/ocm/api/healthz")
	if err != nil {
		t.Fatalf("failed to get health endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

// TestBaseURLTracksListenerNotPublicOrigin guards against a harness regression:
// when a test patches cfg.PublicOrigin to an advertised origin, the server still
// listens on the ephemeral local port. TestServer.BaseURL must remain the real
// local request target (localhost:<allocated port>) so local test traffic and
// readiness probing keep working regardless of the advertised origin.
func TestBaseURLTracksListenerNotPublicOrigin(t *testing.T) {
	ts := harness.StartTestServerWithConfig(t, func(cfg *config.Config) {
		cfg.PublicOrigin = "https://advertised.example.com"
	})
	defer ts.Stop(t)

	if !strings.HasPrefix(ts.BaseURL, "http://localhost:") {
		t.Fatalf("BaseURL should target the local listener, got %q", ts.BaseURL)
	}
	if strings.Contains(ts.BaseURL, "advertised.example.com") {
		t.Fatalf("BaseURL must not use the advertised PublicOrigin, got %q", ts.BaseURL)
	}

	resp, err := http.Get(ts.BaseURL + "/api/healthz")
	if err != nil {
		t.Fatalf("health check against local listener failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected healthz 200 from local listener, got %d", resp.StatusCode)
	}
}

func TestDiscoveryEndpoint(t *testing.T) {
	ts := harness.StartTestServer(t)
	defer ts.Stop(t)

	resp, err := http.Get(ts.BaseURL + "/.well-known/ocm")
	if err != nil {
		t.Fatalf("failed to get discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", contentType)
	}

	var disc struct {
		Enabled       bool   `json:"enabled"`
		APIVersion    string `json:"apiVersion"`
		EndPoint      string `json:"endPoint"`
		Provider      string `json:"provider"`
		ResourceTypes []struct {
			Name string `json:"name"`
		} `json:"resourceTypes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatalf("failed to decode discovery response: %v", err)
	}

	if !disc.Enabled {
		t.Error("expected enabled=true")
	}
	if disc.APIVersion != "1.2.2" {
		t.Errorf("expected apiVersion '1.2.2', got %q", disc.APIVersion)
	}
	if disc.Provider != "OpenCloudMesh" {
		t.Errorf("expected provider 'OpenCloudMesh', got %q", disc.Provider)
	}
	if len(disc.ResourceTypes) == 0 {
		t.Error("expected at least one resource type")
	}
}

func TestLegacyDiscoveryEndpoint(t *testing.T) {
	ts := harness.StartTestServer(t)
	defer ts.Stop(t)

	// /ocm-provider should return JSON directly (no redirect)
	resp, err := http.Get(ts.BaseURL + "/ocm-provider")
	if err != nil {
		t.Fatalf("failed to get legacy endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", contentType)
	}

	// Should return the same discovery JSON as /.well-known/ocm
	var disc struct {
		Enabled    bool   `json:"enabled"`
		APIVersion string `json:"apiVersion"`
		Provider   string `json:"provider"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatalf("failed to decode discovery response: %v", err)
	}

	if !disc.Enabled {
		t.Error("expected enabled=true")
	}
	if disc.APIVersion != "1.2.2" {
		t.Errorf("expected apiVersion '1.2.2', got %q", disc.APIVersion)
	}
	if disc.Provider != "OpenCloudMesh" {
		t.Errorf("expected provider 'OpenCloudMesh', got %q", disc.Provider)
	}
}
