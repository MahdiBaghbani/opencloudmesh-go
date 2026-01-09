// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestTwoInstanceDiscovery verifies that two instances can discover each other.
func TestTwoInstanceDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	h := harness.StartTwoInstances(t,
		harness.SubprocessConfig{Name: "instance1", Mode: "dev"},
		harness.SubprocessConfig{Name: "instance2", Mode: "dev"},
	)
	defer h.Stop(t)

	// Both instances should serve discovery endpoints
	for _, srv := range []*harness.SubprocessServer{h.Server1, h.Server2} {
		resp, err := http.Get(srv.BaseURL + "/.well-known/ocm")
		if err != nil {
			h.DumpLogs(t)
			t.Fatalf("failed to get discovery from %s: %v", srv.Name, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: expected status 200, got %d", srv.Name, resp.StatusCode)
		}

		var disc struct {
			Enabled  bool   `json:"enabled"`
			Provider string `json:"provider"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
			t.Fatalf("%s: failed to decode discovery: %v", srv.Name, err)
		}

		if !disc.Enabled {
			t.Errorf("%s: expected enabled=true", srv.Name)
		}
	}
}

// TestTwoInstanceCrossDiscovery verifies instance1 can discover instance2 via /ocm-aux/discover.
func TestTwoInstanceCrossDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	h := harness.StartTwoInstances(t,
		harness.SubprocessConfig{Name: "instance1", Mode: "dev"},
		harness.SubprocessConfig{Name: "instance2", Mode: "dev"},
	)
	defer h.Stop(t)

	// Instance1 should be able to discover instance2 through its /ocm-aux/discover endpoint
	// Uses base= parameter (not peer=) with the target server's base URL
	// SSRF protection is off in dev mode, so cross-instance discovery should succeed
	discoverURL := h.Server1.BaseURL + "/ocm-aux/discover?base=" + h.Server2.BaseURL
	resp, err := http.Get(discoverURL)
	if err != nil {
		h.DumpLogs(t)
		t.Fatalf("failed to call /ocm-aux/discover: %v", err)
	}
	defer resp.Body.Close()

	// Assert 200 status - cross-discovery should succeed in dev mode
	if resp.StatusCode != http.StatusOK {
		h.DumpLogs(t)
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Assert proper JSON response structure
	var discoverResp struct {
		Success   bool `json:"success"`
		Discovery *struct {
			Enabled  bool   `json:"enabled"`
			Provider string `json:"provider"`
			EndPoint string `json:"endPoint"`
		} `json:"discovery"`
		Error string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discoverResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !discoverResp.Success {
		t.Errorf("expected success=true, got error: %s", discoverResp.Error)
	}
	if discoverResp.Discovery == nil {
		t.Fatal("expected discovery object in response")
	}
	if !discoverResp.Discovery.Enabled {
		t.Error("expected discovery.enabled=true")
	}
	if discoverResp.Discovery.Provider != "OpenCloudMesh" {
		t.Errorf("expected provider 'OpenCloudMesh', got %q", discoverResp.Discovery.Provider)
	}
	t.Logf("cross-discovery succeeded: endpoint=%s", discoverResp.Discovery.EndPoint)
}

// TestSSRFBlockingWithIPLiterals verifies SSRF protection blocks private IPs.
// This test uses IP literals to avoid DNS lookups and ensure no external network access.
func TestSSRFBlockingWithIPLiterals(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	// Start a single server with strict SSRF mode
	// Note: "strict" mode preset enables SSRF blocking via config.Load() defaults
	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "ssrf-test",
		Mode: "strict",
		// ExtraConfig is intentionally empty - strict mode already sets appropriate SSRF settings
	})
	defer srv.Stop(t)

	// Try to discover private IPs - should be blocked by SSRF protection with 403
	privateIPs := []string{
		"http://127.0.0.1:8080",   // Loopback
		"http://10.0.0.1:8080",    // RFC 1918 Class A
		"http://172.16.0.1:8080",  // RFC 1918 Class B
		"http://192.168.1.1:8080", // RFC 1918 Class C
		"http://169.254.1.1:8080", // Link-local
		"http://[::1]:8080",       // IPv6 loopback
	}

	for _, privateIP := range privateIPs {
		t.Run(privateIP, func(t *testing.T) {
			// Use base= parameter (not peer=)
			discoverURL := srv.BaseURL + "/ocm-aux/discover?base=" + privateIP
			resp, err := http.Get(discoverURL)
			if err != nil {
				t.Fatalf("failed to call /ocm-aux/discover: %v", err)
			}
			defer resp.Body.Close()

			// Assert 403 Forbidden - SSRF protection should block private IPs
			if resp.StatusCode != http.StatusForbidden {
				srv.DumpLogs(t)
				t.Fatalf("expected 403 Forbidden for SSRF-blocked IP %s, got %d", privateIP, resp.StatusCode)
			}

			// Assert proper JSON error response
			var discoverResp struct {
				Success bool   `json:"success"`
				Error   string `json:"error,omitempty"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&discoverResp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if discoverResp.Success {
				t.Errorf("expected success=false for SSRF-blocked IP")
			}
			if discoverResp.Error == "" {
				t.Errorf("expected non-empty error message for SSRF-blocked IP")
			}
			t.Logf("SSRF blocked %s: %s", privateIP, discoverResp.Error)
		})
	}
}

// TestHealthEndpointSubprocess verifies health endpoint works via subprocess.
func TestHealthEndpointSubprocess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "health-test",
		Mode: "dev",
	})
	defer srv.Stop(t)

	resp, err := http.Get(srv.BaseURL + "/api/healthz")
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var health struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("failed to decode health: %v", err)
	}

	if health.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", health.Status)
	}
}
