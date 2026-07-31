// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
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
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.BaseURL+"/.well-known/ocm", nil)
		if err != nil {
			t.Fatalf("build discovery request for %s: %v", srv.Name, err)
		}

		resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
		if err != nil {
			h.DumpLogs(t)
			t.Fatalf("failed to get discovery from %s: %v", srv.Name, err)
		}
		defer tshttp.MustClose(t, resp.Body)

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

// TestTwoInstanceCrossDiscovery verifies instance1 can reach instance2 via /ocm-aux/discover.
// Dev instances expose OCM discovery but not inviteAcceptDialog, so the helper returns a
// reason-coded failure after successful upstream discovery (T7a).
func TestTwoInstanceCrossDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	h := harness.StartTwoInstances(t,
		harness.SubprocessConfig{Name: "instance1", Mode: "dev"},
		harness.SubprocessConfig{Name: "instance2", Mode: "dev"},
	)
	defer h.Stop(t)

	discoverURL := h.Server1.BaseURL + "/ocm-aux/discover?base=" + h.Server2.BaseURL

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, discoverURL, nil)
	if err != nil {
		t.Fatalf("build discover request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		h.DumpLogs(t)
		t.Fatalf("failed to call /ocm-aux/discover: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		h.DumpLogs(t)
		t.Fatalf("expected status 502, got %d", resp.StatusCode)
	}

	var discoverResp struct {
		Success    bool   `json:"success"`
		Error      string `json:"error"`
		ReasonCode string `json:"reasonCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discoverResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if discoverResp.Success {
		t.Fatal("expected success=false when peer lacks inviteAcceptDialog")
	}

	if discoverResp.ReasonCode != "no_invite_accept_dialog" {
		t.Fatalf("reasonCode = %q, want no_invite_accept_dialog", discoverResp.ReasonCode)
	}

	if discoverResp.Error == "" {
		t.Fatal("expected friendly error message")
	}

	t.Logf("cross-discovery reached peer but helper failed as expected: %s", discoverResp.Error)
}

// TestSSRFBlockingWithIPLiterals verifies SSRF protection blocks private IPs.
// This test uses IP literals to avoid DNS lookups and ensure no external network access.
func TestSSRFBlockingWithIPLiterals(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	// Start a single server with SSRF blocking enabled (strict mode with route-policy governance).
	binaryPath := harness.BuildBinary(t)

	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "ssrf-test",
		Mode: "strict",
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

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, discoverURL, nil)
			if err != nil {
				t.Fatalf("build discover request: %v", err)
			}

			resp, err := srv.Client().Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
			if err != nil {
				t.Fatalf("failed to call /ocm-aux/discover: %v", err)
			}
			defer tshttp.MustClose(t, resp.Body)

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

// TestSSRFRoutePolicyAllowsExplicitCIDRDiscover proves the positive SSRF path: an
// active route policy with explicit host suffix, CIDR, and port allowance permits
// a private destination that strict mode would otherwise block. The source runs in
// strict mode, the target in dev mode. The discover helper
// may still return no_invite_accept_dialog after upstream discovery succeeds (T7a).
func TestSSRFRoutePolicyAllowsExplicitCIDRDiscover(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	loopbackHost := requireLoopbackHostname(t)
	binaryPath := harness.BuildBinary(t)

	// Start the target first so its dynamic port is known before writing source config.
	target := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:             "ssrf-cidr-target",
		Mode:             "dev",
		PublicOriginHost: loopbackHost,
	})
	defer target.Stop(t)

	source := startSSRFRoutePolicySource(t, binaryPath, loopbackHost, target.Port)
	defer source.Stop(t)

	assertDiscoverAllowedByRoutePolicy(t, source, target, loopbackHost)
}

// requireLoopbackHostname returns the local hostname, skipping when it does
// not resolve into 127.0.0.0/8.
func requireLoopbackHostname(t *testing.T) string {
	t.Helper()

	loopbackHost, err := os.Hostname()
	if err != nil {
		t.Fatalf("hostname: %v", err)
	}

	ips, err := net.DefaultResolver.LookupIP(t.Context(), "ip", loopbackHost)
	if err != nil {
		t.Fatalf("lookup %q: %v", loopbackHost, err)
	}

	resolvesLoopback := false

	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && v4[0] == 127 {
			resolvesLoopback = true
			break
		}
	}

	if !resolvesLoopback {
		t.Skipf("hostname %q does not resolve to an IPv4 address in 127.0.0.0/8", loopbackHost)
	}

	return loopbackHost
}

// startSSRFRoutePolicySource starts the strict source server with a route
// policy that explicitly allows the local hostname, 127.0.0.0/8, and the
// target's port. use_env_fallback is disabled so ambient HTTP_PROXY/HTTPS_PROXY
// env vars cannot interfere with the loopback discovery request.
func startSSRFRoutePolicySource(t *testing.T, binaryPath, loopbackHost string, targetPort int) *harness.SubprocessServer {
	t.Helper()

	return harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "ssrf-cidr-source",
		Mode:                  "strict",
		DisableUseEnvFallback: true,
		ExtraConfig: fmt.Sprintf(`
[outbound_http.ssrf]
mode = "strict"
route_policy = "loopback"

[outbound_http.ssrf.route_policies.loopback]
allow_private_host_suffixes = [%q]
allow_private_cidrs = ["127.0.0.0/8", "::1/128"]
allowed_ports = [%d]
allow_ip_literals = false
`, loopbackHost, targetPort),
	})
}

// assertDiscoverAllowedByRoutePolicy proves the route policy permits the
// private destination: the request passes SSRF (no 403) and upstream
// discovery proceeds, surfacing no_invite_accept_dialog.
func assertDiscoverAllowedByRoutePolicy(t *testing.T, source, target *harness.SubprocessServer, loopbackHost string) {
	t.Helper()

	discoverURL := fmt.Sprintf("%s/ocm-aux/discover?base=http://%s:%d", source.BaseURL, loopbackHost, target.Port)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, discoverURL, nil)
	if err != nil {
		t.Fatalf("build discover request: %v", err)
	}

	resp, err := noProxyClient(source.Client()).Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		source.DumpLogs(t)
		target.DumpLogs(t)
		t.Fatalf("failed to call /ocm-aux/discover: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode == http.StatusForbidden {
		source.DumpLogs(t)
		target.DumpLogs(t)
		t.Fatalf("route policy should allow %s:%d, got 403 Forbidden", loopbackHost, target.Port)
	}

	if resp.StatusCode != http.StatusBadGateway {
		source.DumpLogs(t)
		target.DumpLogs(t)
		t.Fatalf("expected 502 after route-policy-permitted discovery, got %d", resp.StatusCode)
	}

	var discoverResp struct {
		Success    bool   `json:"success"`
		Error      string `json:"error"`
		ReasonCode string `json:"reasonCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discoverResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if discoverResp.Success {
		t.Fatal("expected success=false when target lacks inviteAcceptDialog")
	}

	if discoverResp.ReasonCode != "no_invite_accept_dialog" {
		t.Fatalf("reasonCode = %q, want no_invite_accept_dialog", discoverResp.ReasonCode)
	}

	if discoverResp.Error == "" {
		t.Fatal("expected friendly error message")
	}

	t.Logf("SSRF route policy allowed %s:%d; discover helper failed as expected: %s", loopbackHost, target.Port, discoverResp.Error)
}

// noProxyClient returns a copy of client with the ambient proxy disabled.
// Without this, HTTP_PROXY/HTTPS_PROXY env vars in the test environment could
// intercept calls to loopback and break hermetic SSRF proofs.
func noProxyClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	clone := *client

	var transport *http.Transport
	if base, ok := client.Transport.(*http.Transport); ok {
		transport = base.Clone()
	} else if client.Transport == nil {
		if base, ok := http.DefaultTransport.(*http.Transport); ok {
			transport = base.Clone()
		} else {
			transport = &http.Transport{}
		}
	} else {
		transport = &http.Transport{}
	}

	transport.Proxy = nil

	clone.Transport = transport
	if clone.Timeout == 0 {
		clone.Timeout = 30 * time.Second
	}

	return &clone
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
		Name: "ssrf-control-target",
		Mode: "dev",
	})
	defer target.Stop(t)

	// Source: strict mode, no route policy override. 127.0.0.1 stays blocked by
	// strict SSRF defaults. use_env_fallback disabled for a hermetic client call.
	source := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "ssrf-control-source",
		Mode:                  "strict",
		DisableUseEnvFallback: true,
	})
	defer source.Stop(t)

	discoverURL := fmt.Sprintf("%s/ocm-aux/discover?base=http://127.0.0.1:%d", source.BaseURL, target.Port)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, discoverURL, nil)
	if err != nil {
		t.Fatalf("build discover request: %v", err)
	}

	resp, err := noProxyClient(source.Client()).Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		source.DumpLogs(t)
		target.DumpLogs(t)
		t.Fatalf("failed to call /ocm-aux/discover: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

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
		Name: "health-test",
		Mode: "dev",
	})
	defer srv.Stop(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.BaseURL+"/api/healthz", nil)
	if err != nil {
		t.Fatalf("build health request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("failed to get health: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

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
