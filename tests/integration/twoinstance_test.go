// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestTwoInstanceDiscovery verifies that two instances can discover each other.
func TestTwoInstanceDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	h := harness.StartTwoInstances(t,
		harness.SubprocessConfig{Name: "instance1", Mode: "dev", KeepSignatureDefaults: true},
		harness.SubprocessConfig{Name: "instance2", Mode: "dev", KeepSignatureDefaults: true},
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
		harness.SubprocessConfig{Name: "instance1", Mode: "dev", KeepSignatureDefaults: true},
		harness.SubprocessConfig{Name: "instance2", Mode: "dev", KeepSignatureDefaults: true},
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

	// Start a single server with SSRF blocking enabled.
	// The compat preset keeps SSRF strict while still fitting the plain-HTTP harness.
	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "ssrf-test",
		Mode:                  "compat",
		KeepSignatureDefaults: true,
		// ExtraConfig is intentionally empty - compat mode enables SSRF blocking by default.
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

// TestSSRFRoutePolicyAllowsExplicitCIDRDiscover proves the positive path: an
// active SSRF route policy with explicit CIDR and port allowance permits a
// private destination that strict mode would otherwise block. The source runs
// in compat mode (SSRF strict by preset), the target in dev mode. The route
// policy uses allow_ip_literals=true with 127.0.0.0/8 and the target's dynamic
// port so that 127.0.0.1:<port> passes all three SSRF checks (ip_literals
// allowed, IP in CIDR, port in allowed list). "localhost" is hard-blocked by
// the SSRF engine regardless of policy, so 127.0.0.1 is used directly.
// allow_ip_literals=true is permitted under compat's unbounded compatibility_scope.
func TestSSRFRoutePolicyAllowsExplicitCIDRDiscover(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)

	// Start the target first so its dynamic port is known before writing source config.
	target := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "ssrf-cidr-target",
		Mode:                  "dev",
		KeepSignatureDefaults: true,
	})
	defer target.Stop(t)

	// Source: compat mode inherits SSRF strict by default (same baseline as
	// TestSSRFBlockingWithIPLiterals). The route policy explicitly allows
	// 127.0.0.0/8 and the target's port with IP literals enabled.
	// proxy_env_fallback is disabled so ambient HTTP_PROXY/HTTPS_PROXY env vars
	// cannot interfere with the loopback discovery request.
	source := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                    "ssrf-cidr-source",
		Mode:                    "compat",
		KeepSignatureDefaults:   true,
		DisableProxyEnvFallback: true,
		ExtraConfig: fmt.Sprintf(`
[outbound_http.ssrf]
mode = "strict"
route_policy = "loopback"

[outbound_http.ssrf.route_policies.loopback]
allow_private_cidrs = ["127.0.0.0/8"]
allowed_ports = [%d]
allow_ip_literals = true
`, target.Port),
	})
	defer source.Stop(t)

	discoverURL := fmt.Sprintf("%s/ocm-aux/discover?base=http://127.0.0.1:%d", source.BaseURL, target.Port)
	resp, err := noProxyLocalhostClient(30 * time.Second).Get(discoverURL)
	if err != nil {
		source.DumpLogs(t)
		target.DumpLogs(t)
		t.Fatalf("failed to call /ocm-aux/discover: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		source.DumpLogs(t)
		target.DumpLogs(t)
		t.Fatalf("expected 200 OK from route-policy-allowed private destination, got %d", resp.StatusCode)
	}

	var discoverResp struct {
		Success   bool `json:"success"`
		Discovery *struct {
			Enabled  bool   `json:"enabled"`
			Provider string `json:"provider"`
		} `json:"discovery"`
		Error string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discoverResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !discoverResp.Success {
		t.Errorf("expected success=true from route-policy-permitted destination, got error: %s", discoverResp.Error)
	}
	if discoverResp.Discovery == nil {
		t.Fatal("expected discovery object in response")
	}
	if !discoverResp.Discovery.Enabled {
		t.Error("expected discovery.enabled=true")
	}
	t.Logf("SSRF route policy allowed private destination 127.0.0.1:%d; provider=%s", target.Port, discoverResp.Discovery.Provider)
}

// noProxyLocalhostClient returns an HTTP client with the ambient proxy disabled.
// Without this, HTTP_PROXY/HTTPS_PROXY env vars in the test environment could
// intercept calls to 127.0.0.1 and break the hermetic proof.
func noProxyLocalhostClient(timeout time.Duration) *http.Client {
	var t *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		t = base.Clone()
	} else {
		t = &http.Transport{}
	}
	t.Proxy = nil
	return &http.Client{Timeout: timeout, Transport: t}
}

// TestSSRFRoutePolicyBlocksWithoutAllowance is the control proof for
// TestSSRFRoutePolicyAllowsExplicitCIDRDiscover. It verifies that the same
// private-destination discover request is blocked (403) when no explicit
// route policy allowance is present, so the positive test is not vacuously green.
func TestSSRFRoutePolicyBlocksWithoutAllowance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)

	target := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "ssrf-control-target",
		Mode:                  "dev",
		KeepSignatureDefaults: true,
	})
	defer target.Stop(t)

	// Source: compat mode, no route policy override. 127.0.0.1 stays blocked by
	// strict SSRF defaults. proxy_env_fallback disabled for a hermetic client call.
	source := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                    "ssrf-control-source",
		Mode:                    "compat",
		KeepSignatureDefaults:   true,
		DisableProxyEnvFallback: true,
	})
	defer source.Stop(t)

	discoverURL := fmt.Sprintf("%s/ocm-aux/discover?base=http://127.0.0.1:%d", source.BaseURL, target.Port)
	resp, err := noProxyLocalhostClient(30 * time.Second).Get(discoverURL)
	if err != nil {
		source.DumpLogs(t)
		target.DumpLogs(t)
		t.Fatalf("failed to call /ocm-aux/discover: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		source.DumpLogs(t)
		target.DumpLogs(t)
		t.Fatalf("expected 403 Forbidden without route policy allowance, got %d", resp.StatusCode)
	}

	var discoverResp struct {
		Success bool   `json:"success"`
		Error   string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discoverResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if discoverResp.Success {
		t.Error("expected success=false without route policy allowance")
	}
	t.Logf("SSRF blocked 127.0.0.1:%d without route policy: %s", target.Port, discoverResp.Error)
}

// TestHealthEndpointSubprocess verifies health endpoint works via subprocess.
func TestHealthEndpointSubprocess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "health-test",
		Mode:                  "dev",
		KeepSignatureDefaults: true,
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
