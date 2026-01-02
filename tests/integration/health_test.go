package integration

import (
	"encoding/json"
	"net/http"
	"testing"

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

func TestDiscoveryEndpoints(t *testing.T) {
	ts := harness.StartTestServer(t)
	defer ts.Stop(t)

	// Both discovery endpoints should return 200 with valid JSON
	endpoints := []string{
		"/.well-known/ocm",
		"/ocm-provider",
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			resp, err := http.Get(ts.BaseURL + endpoint)
			if err != nil {
				t.Fatalf("failed to get %s: %v", endpoint, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status 200 for %s, got %d", endpoint, resp.StatusCode)
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
		})
	}
}

