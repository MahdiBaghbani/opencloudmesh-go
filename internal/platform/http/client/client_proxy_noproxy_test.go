// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package client_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	outboundtestutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

// TestClient_NOProxy_DirectPathSSRFStillBlocks verifies that NO_PROXY changing
// routing to direct never bypasses strict-mode SSRF destination checks.
// The client still uses env fallback, but private/loopback targets are blocked
// by the preflight check in DoWithOptions before any dial or proxy decision.
func TestClient_NOProxy_DirectPathSSRFStillBlocks(t *testing.T) {
	var proxyHit atomic.Bool

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHit.Store(true)
		t.Error("proxy must not be reached for SSRF-blocked destinations")
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	t.Setenv("REQUEST_METHOD", "")
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	// NO_PROXY directs these addresses to bypass the proxy and go direct.
	// SSRF must still block them regardless.
	t.Setenv("NO_PROXY", "192.168.1.1,10.0.0.1,127.0.0.1")
	t.Setenv("no_proxy", "192.168.1.1,10.0.0.1,127.0.0.1")

	cfg := outboundtestutil.StrictNoneOutboundConfig()
	cfg.UseEnvFallback = true
	c := httpclient.New(cfg, nil)

	privateTargets := []string{
		"http://192.168.1.1/resource",
		"http://10.0.0.1/resource",
		"http://127.0.0.1/resource",
	}

	for _, target := range privateTargets {
		t.Run(target, func(t *testing.T) {
			resp, err := c.Get(context.Background(), target) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
			if resp != nil {
				defer outboundtestutil.MustClose(t, resp.Body)
			}

			if err == nil {
				t.Errorf("expected SSRF error for %s even with NO_PROXY bypass", target)

				return
			}

			if !httpclient.IsSSRFError(err) {
				t.Errorf("expected SSRF error for %s, got: %v", target, err)
			}
		})
	}

	if proxyHit.Load() {
		t.Error("proxy must not be hit; preflight SSRF check must fire first")
	}
}

// findNonLoopbackIPv4 returns the first non-loopback, non-link-local IPv4
// address that can be listened on, or nil if none is available. It is used
// by TestClient_NOProxy_RoutingBypass to obtain a destination IP that Go's
// env-driven proxy logic does not special-case the way it does for loopback.
func findNonLoopbackIPv4(t *testing.T, ctx context.Context) net.IP {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.To4() == nil {
				continue
			}
			// Confirm we can actually bind a listener on this address.
			if l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", ip.String()+":0"); err == nil {
				outboundtestutil.MustClose(t, l)

				return ip.To4()
			}
		}
	}

	return nil
}

// TestClient_NOProxy_RoutingBypass verifies that when NO_PROXY matches the
// destination host the client bypasses the env proxy and connects directly.
// This is the routing complement to TestClient_NOProxy_DirectPathSSRFStillBlocks,
// which covers the security invariant: strict-mode SSRF blocking is not weakened
// by a NO_PROXY-driven direct path.
//
// Design note: the destination must run on a non-loopback address.
// Go's env-driven proxy logic unconditionally skips proxies for loopback IPs
// (127.x and ::1) regardless of NO_PROXY, so using httptest.NewServer (which
// always binds to 127.0.0.1) would conflate Go's built-in loopback bypass with
// the NO_PROXY bypass and prove nothing about NO_PROXY routing. A non-loopback
// local IP ensures that without NO_PROXY the proxy would be contacted, and
// with NO_PROXY matching the IP it is not.
func TestClient_NOProxy_RoutingBypass(t *testing.T) {
	localIP := findNonLoopbackIPv4(t, t.Context())
	if localIP == nil {
		t.Skip("no non-loopback IPv4 interface available; skipping NO_PROXY routing test")
	}

	var proxyHit atomic.Bool

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit.Store(true)
		t.Errorf("proxy must not be contacted when NO_PROXY matches destination: got %s %s",
			r.Method, r.RequestURI)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()

	// Destination server on a non-loopback IP so Go does not special-case it
	// independently of NO_PROXY.
	destListener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", localIP.String()+":0")
	if err != nil {
		t.Fatalf("listen on non-loopback IP %s: %v", localIP, err)
	}

	destSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)

		if _, werr := w.Write([]byte("direct")); werr != nil {
			t.Errorf("write response: %v", werr)
		}
	}))
	destSrv.Listener = destListener

	destSrv.Start()
	defer destSrv.Close()

	destURL := destSrv.URL + "/resource"
	destHost := localIP.String()

	t.Setenv("REQUEST_METHOD", "")
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", destHost)
	t.Setenv("no_proxy", destHost)
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")

	// SSRF off: destination is a local non-loopback IP used for the routing test.
	cfg := outboundtestutil.PermissiveConfig()
	cfg.UseEnvFallback = true
	// Construct after setting env so proxy host detection matches the env
	// proxy configuration used by the transport.
	c := httpclient.New(cfg, nil)

	resp, err := c.Get(context.Background(), destURL) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("expected direct connection via NO_PROXY bypass, got error: %v", err)
	}
	defer outboundtestutil.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	if proxyHit.Load() {
		t.Error("proxy was contacted despite NO_PROXY matching the destination IP")
	}
}
