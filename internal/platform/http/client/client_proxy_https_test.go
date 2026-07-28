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
		_, _ = w.Write([]byte("tls-backend-ok")) //nolint:errcheck // test handler response write
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

	// Minimal CONNECT-capable proxy: records CONNECT semantics and tunnels
	// bytes to the real backend.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		targetConn, dialErr := net.Dial("tcp", r.Host) //nolint:gosec // test: r.Host is a test-controlled host header, not user-supplied URL input
		if dialErr != nil {
			http.Error(w, dialErr.Error(), http.StatusBadGateway)
			return
		}

		clientConn, _, hijackErr := hijacker.Hijack()
		if hijackErr != nil {
			targetConn.Close() //nolint:errcheck // test proxy cleanup after hijack failure
			t.Logf("proxy: hijack error: %v", hijackErr)

			return
		}

		_, _ = fmt.Fprint(clientConn, "HTTP/1.1 200 Connection established\r\n\r\n") //nolint:errcheck // test CONNECT tunnel handshake

		// Proxy bytes bidirectionally until both sides close.
		var wg sync.WaitGroup

		wg.Add(2)
		go func() {
			defer wg.Done()
			defer targetConn.Close() //nolint:errcheck // test tunnel relay teardown

			_, _ = io.Copy(targetConn, clientConn) //nolint:errcheck // test tunnel byte relay
		}()
		go func() {
			defer wg.Done()
			defer clientConn.Close() //nolint:errcheck // test tunnel relay teardown

			_, _ = io.Copy(clientConn, targetConn) //nolint:errcheck // test tunnel byte relay
		}()
		// Do not block the handler goroutine: that would cause proxy.Close()
		// (and therefore the test) to hang while the client holds the tunnel
		// open via HTTP keep-alive. Instead register a cleanup that force-
		// expires both connections so the io.Copy goroutines unblock promptly.
		t.Cleanup(func() {
			past := time.Now().Add(-time.Second)
			_ = clientConn.SetDeadline(past) //nolint:errcheck // test tunnel teardown force close
			_ = targetConn.SetDeadline(past) //nolint:errcheck // test tunnel teardown force close

			wg.Wait()
		})
	}))
	defer proxy.Close()

	// Build a cert pool trusting the backend's self-signed TLS certificate.
	serverCert := backend.TLS.Certificates[0]

	x509Cert, parseErr := x509.ParseCertificate(serverCert.Certificate[0])
	if parseErr != nil {
		t.Fatalf("parse backend TLS cert: %v", parseErr)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(x509Cert)

	// SSRF off: backend is 127.0.0.1; SSRF bypass is intentional here because we
	// are testing CONNECT tunnel semantics, not SSRF enforcement. The companion
	// test TestClient_HTTPSPrivateDestinationBlockedWithProxy covers that
	// preflight blocks private HTTPS targets before CONNECT.
	cfg := outboundtestutil.PermissiveConfig()
	cfg.ProxyURL = proxy.URL
	c := httpclient.New(cfg, rootCAs)

	resp, err := c.Get(context.Background(), backend.URL)
	if err != nil {
		t.Fatalf("HTTPS through CONNECT proxy failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test response body close

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
			resp, err := c.Get(context.Background(), target)
			if resp != nil {
				defer resp.Body.Close() //nolint:errcheck // test response body close
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
