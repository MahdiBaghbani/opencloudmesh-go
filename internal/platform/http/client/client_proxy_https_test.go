// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package client_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	outboundtestutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

// TestClient_HTTPSProxyCONNECT verifies that HTTPS destinations are tunneled
// through the configured proxy using HTTP CONNECT (RFC 7231 s4.3.6), and that
// the proxy observes a correct CONNECT host:port request before the TLS
// handshake proceeds.
func TestClient_HTTPSProxyCONNECT(t *testing.T) {
	// HTTPS backend - the final TLS destination reached through the tunnel.
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)

		if _, err := w.Write([]byte("tls-backend-ok")); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer backend.Close()

	backendParsed, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}

	wantCONNECTTarget := backendParsed.Host // "127.0.0.1:PORT"

	var (
		connectSeen           atomic.Bool
		observedCONNECTTarget atomic.Value
	)

	proxy := newCONNECTRecordingProxy(t, &connectSeen, &observedCONNECTTarget)
	defer proxy.Close()

	rootCAs := backendTLSCertPool(t, backend)

	// SSRF off: backend is 127.0.0.1; SSRF bypass is intentional here because we
	// are testing CONNECT tunnel semantics, not SSRF enforcement. The companion
	// test TestClient_HTTPSPrivateDestinationBlockedWithProxy covers that
	// preflight blocks private HTTPS targets before CONNECT.
	cfg := outboundtestutil.PermissiveConfig()
	cfg.ProxyURL = proxy.URL
	c := httpclient.New(cfg, rootCAs)

	resp, err := c.Get(context.Background(), backend.URL) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("HTTPS through CONNECT proxy failed: %v", err)
	}
	defer outboundtestutil.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	if !connectSeen.Load() {
		t.Error("proxy did not receive a CONNECT request")
	}

	if got, ok := observedCONNECTTarget.Load().(string); !ok || got != wantCONNECTTarget {
		t.Errorf("CONNECT target: got %q, want %q", got, wantCONNECTTarget)
	}
}

// backendTLSCertPool builds a cert pool trusting the test backend's
// self-signed TLS certificate.
func backendTLSCertPool(t *testing.T, backend *httptest.Server) *x509.CertPool {
	t.Helper()

	serverCert := backend.TLS.Certificates[0]

	x509Cert, parseErr := x509.ParseCertificate(serverCert.Certificate[0])
	if parseErr != nil {
		t.Fatalf("parse backend TLS cert: %v", parseErr)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(x509Cert)

	return rootCAs
}

// newCONNECTRecordingProxy starts a minimal CONNECT-capable proxy that records
// CONNECT semantics and tunnels bytes to the real backend.
func newCONNECTRecordingProxy(t *testing.T, connectSeen *atomic.Bool, observedCONNECTTarget *atomic.Value) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Errorf("proxy: expected CONNECT, got %s %s", r.Method, r.RequestURI)
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		connectSeen.Store(true)
		// r.RequestURI is "host:port" for CONNECT requests.
		observedCONNECTTarget.Store(r.RequestURI)

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("proxy: hijacking not supported")
			http.Error(w, "hijacking not supported", http.StatusInternalServerError)

			return
		}

		// r.Host is the test-controlled CONNECT target, not user-supplied URL input.
		targetConn, dialErr := (&net.Dialer{}).DialContext(r.Context(), "tcp", r.Host)
		if dialErr != nil {
			http.Error(w, dialErr.Error(), http.StatusBadGateway)
			return
		}

		clientConn, _, hijackErr := hijacker.Hijack()
		if hijackErr != nil {
			outboundtestutil.MustClose(t, targetConn)
			t.Logf("proxy: hijack error: %v", hijackErr)

			return
		}

		if _, err := fmt.Fprint(clientConn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			t.Errorf("proxy: write CONNECT response: %v", err)
		}

		// Proxy bytes bidirectionally until both sides close.
		var wg sync.WaitGroup

		wg.Add(2)
		go func() {
			defer wg.Done()
			defer outboundtestutil.MustClose(t, targetConn)

			// Relay errors are expected at teardown, when the cleanup forces
			// both connections closed via expired deadlines; log, do not fail.
			if _, err := io.Copy(targetConn, clientConn); err != nil {
				t.Logf("proxy: tunnel relay target<-client stopped: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			defer outboundtestutil.MustClose(t, clientConn)

			if _, err := io.Copy(clientConn, targetConn); err != nil {
				t.Logf("proxy: tunnel relay client<-target stopped: %v", err)
			}
		}()
		// Do not block the handler goroutine: that would cause proxy.Close()
		// (and therefore the test) to hang while the client holds the tunnel
		// open via HTTP keep-alive. Instead register a cleanup that force-
		// expires both connections so the io.Copy goroutines unblock promptly.
		t.Cleanup(func() {
			past := time.Now().Add(-time.Second)

			if err := clientConn.SetDeadline(past); err != nil {
				t.Logf("proxy: clientConn deadline: %v", err)
			}

			if err := targetConn.SetDeadline(past); err != nil {
				t.Logf("proxy: targetConn deadline: %v", err)
			}

			wg.Wait()
		})
	}))
}

// TestClient_HTTPSPrivateDestinationBlockedWithProxy verifies that strict-mode
// SSRF preflight blocks private and loopback HTTPS destinations before any
// CONNECT request is sent to the proxy. This is the HTTPS counterpart to
// TestClient_DestinationPrivateIPBlockedWithProxy.
func TestClient_HTTPSPrivateDestinationBlockedWithProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("proxy reached for blocked destination: %s %s", r.Method, r.RequestURI)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	cfg := outboundtestutil.StrictNoneOutboundConfig()
	cfg.ProxyURL = proxy.URL
	c := httpclient.New(cfg, nil)

	targets := []string{
		"https://192.168.1.1/resource",
		"https://10.0.0.1/resource",
		"https://127.0.0.1/resource",
		"https://[::1]/resource",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			resp, err := c.Get(context.Background(), target) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
			if resp != nil {
				defer outboundtestutil.MustClose(t, resp.Body)
			}

			if err == nil {
				t.Errorf("expected SSRF error for %s, got nil", target)
				return
			}

			if !httpclient.IsSSRFError(err) {
				t.Errorf("expected SSRF error for %s, got: %v", target, err)
			}
		})
	}
}
