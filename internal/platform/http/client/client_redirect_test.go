// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package client_test

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	outboundtestutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestClient_SignedRequestsRejectRedirects(t *testing.T) {
	t.Parallel()

	// Create a server that redirects

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)

			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil)

	// Signed request should fail on redirect
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/redirect", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := client.DoSigned(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if err == nil {
		t.Fatal("expected error for signed request with redirect")
	}

	if !httpclient.IsRedirectError(err) {
		t.Errorf("expected redirect error, got: %v", err)
	}

	if !strings.Contains(err.Error(), "signed requests cannot follow redirects") {
		t.Errorf("expected 'signed requests cannot follow redirects' in error, got: %v", err)
	}
}

func TestClient_UnsignedFollowsOneRedirect(t *testing.T) {
	t.Parallel()
	runSameHostRelativeRedirectTest(
		t,
		"reached target",
		"expected success, got error",
		"expected 2 requests (original + redirect)",
	)
}

func TestClient_UnsignedRejectsTooManyRedirects(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always redirect
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound) //nolint:gosec // test fixture: redirect target is derived from the local test request path, not an attacker-controlled production path
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil) // MaxRedirects=1 by default

	resp, err := client.Get(context.Background(), server.URL+"/start") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if err == nil {
		t.Fatal("expected error for too many redirects")
	}

	if !strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("expected 'too many redirects' in error, got: %v", err)
	}
}

func TestClient_UnsignedRejectsCrossHostRedirect(t *testing.T) {
	t.Parallel()
	runCrossHostRedirectBlockedTest(t, "expected error for cross-host redirect")
}

func TestClient_UnsignedRejectsHTTPSDowngrade(t *testing.T) {
	t.Parallel()

	// HTTP target the redirect will point to. The downgrade check fires before
	// the same-host check, so the target host does not matter for this test.

	httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpTarget.Close()

	// HTTPS source that redirects down to plain HTTP.
	tlsSource := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpTarget.URL+"/target", http.StatusFound)
	}))
	defer tlsSource.Close()

	// Trust the TLS source's self-signed certificate.
	serverCert := tlsSource.TLS.Certificates[0]

	x509Cert, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse TLS cert: %v", err)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(x509Cert)

	c := outboundtestutil.NewPermissive(rootCAs)

	resp, err := c.Get(context.Background(), tlsSource.URL) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if err == nil {
		t.Fatal("expected error for HTTPS->HTTP redirect downgrade")
	}

	if !httpclient.IsRedirectError(err) {
		t.Errorf("expected redirect error, got: %v", err)
	}

	if !strings.Contains(err.Error(), "redirect from https to http blocked") {
		t.Errorf("expected downgrade error message, got: %v", err)
	}
}

func TestSignedNoRedirectViaHeaders(t *testing.T) {
	t.Parallel()

	// Requests with RFC 9421 signature headers must not follow redirects
	// even when using the unsigned Do() path

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)

			return
		}

		w.WriteHeader(http.StatusOK)
	}))

	t.Cleanup(func() { server.Close() })

	client := outboundtestutil.NewPermissive(nil)

	tests := []struct {
		name   string
		header string
	}{
		{"Signature header", "Signature"},
		{"Signature-Input header", "Signature-Input"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/redirect", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}

			req.Header.Set(tt.header, "sig=()")

			// Use Do() not DoSigned() - central header detection should still catch it
			resp, err := client.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
			if resp != nil {
				defer outboundtestutil.MustClose(t, resp.Body)
			}

			if err == nil {
				t.Fatal("expected error for signed request with redirect")
			}

			if !httpclient.IsRedirectError(err) {
				t.Errorf("expected redirect error, got: %v", err)
			}

			if !strings.Contains(err.Error(), "signed requests cannot follow redirects") {
				t.Errorf("expected 'signed requests cannot follow redirects', got: %v", err)
			}
		})
	}
}

func TestRedirectSameHostSemantics(t *testing.T) {
	t.Parallel()

	// Test same-host redirect checks use relative URLs so the server host is preserved
	// This tests that relative redirects work correctly and that port normalization applies

	runSameHostRelativeRedirectTest(
		t,
		"reached",
		"relative redirect should work",
		"expected 2 requests (start + redirect)",
	)
}

func TestRedirectCrossHostBlocked(t *testing.T) {
	t.Parallel()
	runCrossHostRedirectBlockedTest(t, "cross-host redirect should be blocked")
}

func TestIsSameHostPortNormalization(t *testing.T) {
	t.Parallel()

	// Test port normalization logic via a test where we inject port in redirect
	// This simulates: server at :PORT redirects to same host with explicit :PORT

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			// Build absolute URL with explicit port (should still be same-host)
			targetURL := "http://" + r.Host + "/target"
			http.Redirect(w, r, targetURL, http.StatusFound) //nolint:gosec // test fixture: redirect target is built from the local test server host, not an attacker-controlled production path

			return
		}

		if r.URL.Path == "/target" {
			w.WriteHeader(http.StatusOK)

			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil)

	resp, err := client.Get(context.Background(), server.URL+"/start") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("same-host redirect with explicit port should work: %v", err)
	}
	defer outboundtestutil.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestClient_SignedRedirectRejectedWithProxy verifies that signed-request
// redirect rejection is enforced even when an explicit proxy is configured
// and the proxy itself responds with a redirect.
func TestClient_SignedRedirectRejectedWithProxy(t *testing.T) {
	t.Parallel()

	// Proxy responds with a redirect to prove rejection happens at the client,
	// not at the transport level.

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://other.example.invalid/target", http.StatusFound)
	}))
	defer proxy.Close()

	cfg := outboundtestutil.PermissiveConfig()
	cfg.ProxyURL = proxy.URL
	c := httpclient.New(cfg, nil)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://external.example.invalid/resource", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := c.DoSigned(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if err == nil {
		t.Fatal("expected error for signed request receiving redirect via proxy")
	}

	if !httpclient.IsRedirectError(err) {
		t.Errorf("expected redirect error, got: %v", err)
	}

	if !strings.Contains(err.Error(), "signed requests cannot follow redirects") {
		t.Errorf("expected 'signed requests cannot follow redirects', got: %v", err)
	}
}
