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

func TestRootOnlyEndpointsExist(t *testing.T) {
	ts := harness.StartTestServer(t)
	defer ts.Stop(t)

	// These should return 501 Not Implemented (not 404)
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

			// 501 means the route exists but handler is not implemented yet
			if resp.StatusCode != http.StatusNotImplemented {
				t.Errorf("expected status 501 for %s, got %d", endpoint, resp.StatusCode)
			}
		})
	}
}

