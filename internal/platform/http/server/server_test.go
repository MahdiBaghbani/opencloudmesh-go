// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity/sessiongate"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

// trackingService is a test service that records when Close() is called.
type trackingService struct {
	name       string
	prefix     string
	closeOrder *[]string
}

func (t *trackingService) Handler() http.Handler { return http.NotFoundHandler() }
func (t *trackingService) Prefix() string        { return t.prefix }
func (t *trackingService) Close() error {
	*t.closeOrder = append(*t.closeOrder, t.name)
	return nil
}

func testServerDeps(t *testing.T, cfg *config.Config, logger *slog.Logger) ServerDeps {
	t.Helper()

	partyRepo := identity.NewMemoryPartyRepo()
	sessionRepo := identity.NewMemorySessionRepo()
	realIP := realip.NewTrustedProxies(nil)

	return ServerDeps{
		RealIP: realIP,
		AuthGate: func(requireAuth func(string) bool) func(http.Handler) http.Handler {
			return sessiongate.NewAuthGate(sessiongate.AuthGateConfig{
				RequireAuth: requireAuth,
				Log:         logger,
				SessionRepo: sessionRepo,
				PartyRepo:   partyRepo,
				BasePath:    cfg.ExternalBasePath,
			})
		},
	}
}

func TestNew_FailsWithMissingServerDeps(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("empty deps", func(t *testing.T) {
		_, err := New(cfg, logger, nil, ServerDeps{})
		if err == nil {
			t.Fatal("expected error for missing server deps")
		}

		if !errors.Is(err, ErrMissingRealIP) {
			t.Errorf("expected ErrMissingRealIP, got: %v", err)
		}
	})

	t.Run("missing auth gate", func(t *testing.T) {
		sd := ServerDeps{RealIP: realip.NewTrustedProxies(nil)}

		_, err := New(cfg, logger, nil, sd)
		if err == nil {
			t.Fatal("expected error for missing auth gate")
		}

		if !errors.Is(err, ErrMissingAuthGate) {
			t.Errorf("expected ErrMissingAuthGate, got: %v", err)
		}
	})
}

func TestNew_SucceedsWithServerDeps(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	srv, err := New(cfg, logger, nil, testServerDeps(t, cfg, logger))
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if srv == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestShutdown_ClosesServicesInReverseOrder(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	var closeOrder []string

	svc1 := &trackingService{name: "svc1", prefix: "svc1", closeOrder: &closeOrder}
	svc2 := &trackingService{name: "svc2", prefix: "svc2", closeOrder: &closeOrder}
	svc3 := &trackingService{name: "svc3", prefix: "svc3", closeOrder: &closeOrder}

	srv, err := New(cfg, logger, map[string]service.Service{
		"ocmaux": svc1,
		"api":    svc2,
		"ui":     svc3,
	}, testServerDeps(t, cfg, logger))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Shutdown should close services in reverse mount order
	ctx := context.Background()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	// Services mounted in order: svc1, svc2, svc3
	// Should close in reverse: svc3, svc2, svc1
	expected := []string{"svc3", "svc2", "svc1"}
	if len(closeOrder) != len(expected) {
		t.Fatalf("expected %d services closed, got %d: %v", len(expected), len(closeOrder), closeOrder)
	}

	for i, name := range expected {
		if closeOrder[i] != name {
			t.Errorf("close order[%d] = %q, want %q", i, closeOrder[i], name)
		}
	}
}

// Verify trackingService implements service.Service
var _ service.Service = (*trackingService)(nil)

// getFreePort binds to :0, grabs the assigned port, and releases it.
// The port may be reused between close and the real bind, but this is
// acceptable for tests.
func getFreePort(t *testing.T) int {
	t.Helper()

	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("getFreePort: %v", err)
	}

	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("getFreePort: expected TCP address")
	}

	port := addr.Port

	tshttp.MustClose(t, l)

	return port
}

// generateTestCert creates a self-signed cert+key pair and writes them as
// cert.pem and key.pem in dir.
func generateTestCert(t *testing.T, dir string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestACME_TwoListeners(t *testing.T) {
	// Pre-populate cert so Init() takes the fast path (zero network calls).
	storageDir := t.TempDir()
	generateTestCert(t, storageDir)

	httpPort := getFreePort(t)
	httpsPort := getFreePort(t)

	cfg := config.DevConfig()
	cfg.TLS.Mode = "acme"
	cfg.TLS.HTTPPort = httpPort
	cfg.TLS.HTTPSPort = httpsPort
	cfg.TLS.ACME.StorageDir = storageDir
	cfg.TLS.ACME.Domain = "localhost"
	cfg.TLS.ACME.Email = "test@test.local"
	cfg.TLS.ACME.Directory = "https://192.0.2.1:14000/dir" // unreachable; must not be contacted
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.PublicOrigin = fmt.Sprintf("https://localhost:%d", httpsPort)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	srv, err := New(cfg, logger, nil, testServerDeps(t, cfg, logger))
	if err != nil {
		t.Fatalf("server creation failed: %v", err)
	}

	// Start in goroutine; collect the blocking error.
	startErr := make(chan error, 1)
	go func() {
		startErr <- srv.Start()
	}()

	// Wait for both listeners to come up.
	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)
	httpsAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)

	if !waitForListener(t, httpAddr, 3*time.Second) {
		t.Fatal("HTTP listener did not come up")
	}

	if !waitForListener(t, httpsAddr, 3*time.Second) {
		t.Fatal("HTTPS listener did not come up")
	}

	assertUnknownChallenge404(t, httpAddr)
	assertHTTPRedirectsToHTTPS(t, httpAddr, httpsPort)
	assertHTTPSListenerServesTLS(t, httpsAddr)
	shutdownAndDrainStart(t, srv, startErr)
}

// assertUnknownChallenge404 checks the ACME challenge handler returns 404 for
// an unknown token.
func assertUnknownChallenge404(t *testing.T, httpAddr string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://%s/.well-known/acme-challenge/nonexistent", httpAddr), nil)
	if err != nil {
		t.Fatalf("build challenge request failed: %v", err)
	}

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("challenge request failed: %v", err)
	}

	tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for unknown challenge token, got %d", resp.StatusCode)
	}
}

// assertHTTPRedirectsToHTTPS checks a non-challenge HTTP request gets a 308
// redirect to the HTTPS listener.
func assertHTTPRedirectsToHTTPS(t *testing.T, httpAddr string, httpsPort int) {
	t.Helper()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // do not follow redirects
	}}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://%s/some/path?q=1", httpAddr), nil)
	if err != nil {
		t.Fatalf("build redirect request failed: %v", err)
	}

	resp, err := client.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("redirect request failed: %v", err)
	}

	tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("expected 308, got %d", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")

	expected := fmt.Sprintf("https://127.0.0.1:%d/some/path?q=1", httpsPort)
	if loc != expected {
		t.Errorf("redirect Location = %q, want %q", loc, expected)
	}
}

// assertHTTPSListenerServesTLS checks the HTTPS listener completes a TLS
// handshake with the loaded certificate.
func assertHTTPSListenerServesTLS(t *testing.T, httpsAddr string) {
	t.Helper()

	tlsClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &cryptotls.Config{InsecureSkipVerify: true}, //nolint:gosec // test TLS client: InsecureSkipVerify against self-signed test CA
	}}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://%s/", httpsAddr), nil)
	if err != nil {
		t.Fatalf("build HTTPS request failed: %v", err)
	}

	resp, err := tlsClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}

	tshttp.MustClose(t, resp.Body)
	// Any response means the TLS handshake and listener work; the actual
	// status depends on mounted services (404 is fine with nil service map).
	if resp.TLS == nil {
		t.Error("expected TLS connection info, got nil")
	}
}

// shutdownAndDrainStart shuts the server down and checks Start() returns
// http.ErrServerClosed.
func shutdownAndDrainStart(t *testing.T, srv *Server, startErr <-chan error) {
	t.Helper()

	shutCtx, cancel := context.WithTimeout(context.Background(), tshttp.DefaultShutdownWait)
	defer cancel()

	if err := srv.Shutdown(shutCtx); err != nil {
		t.Errorf("shutdown error: %v", err)
	}

	// Start() should return after shutdown (http.ErrServerClosed).
	select {
	case sErr := <-startErr:
		if sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			t.Errorf("unexpected Start() error: %v", sErr)
		}
	case <-time.After(tshttp.DefaultShutdownWait):
		t.Error("Start() did not return after shutdown")
	}
}

func TestACME_MissingPorts(t *testing.T) {
	cfg := config.DevConfig()
	cfg.TLS.Mode = "acme"
	cfg.ListenAddr = "127.0.0.1:0"

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	sd := testServerDeps(t, cfg, logger)

	cfg.TLS.HTTPPort = 0
	cfg.TLS.HTTPSPort = 9443

	srv, err := New(cfg, logger, nil, sd)
	if err != nil {
		t.Fatalf("server creation failed: %v", err)
	}

	if serr := srv.Start(); serr == nil {
		t.Error("expected error for zero HTTPPort")
	}

	cfg.TLS.HTTPPort = 9080
	cfg.TLS.HTTPSPort = 0

	srv, err = New(cfg, logger, nil, sd)
	if err != nil {
		t.Fatalf("server creation failed: %v", err)
	}

	if err := srv.Start(); err == nil {
		t.Error("expected error for zero HTTPSPort")
	}
}

func TestACME_HTTPSBindFailure_StopsChallengeServer(t *testing.T) {
	storageDir := t.TempDir()
	generateTestCert(t, storageDir)

	httpPort := getFreePort(t)
	httpsPort := getFreePort(t)

	// Pre-bind HTTPS port so ACME startup fails during HTTPS bind.
	httpsBlocker, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", httpsPort))
	if err != nil {
		t.Fatalf("failed to pre-bind HTTPS port: %v", err)
	}
	defer tshttp.MustClose(t, httpsBlocker)

	cfg := config.DevConfig()
	cfg.TLS.Mode = "acme"
	cfg.TLS.HTTPPort = httpPort
	cfg.TLS.HTTPSPort = httpsPort
	cfg.TLS.ACME.StorageDir = storageDir
	cfg.TLS.ACME.Domain = "localhost"
	cfg.TLS.ACME.Email = "test@test.local"
	cfg.TLS.ACME.Directory = "https://192.0.2.1:14000/dir"
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.PublicOrigin = fmt.Sprintf("https://localhost:%d", httpsPort)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	srv, err := New(cfg, logger, nil, testServerDeps(t, cfg, logger))
	if err != nil {
		t.Fatalf("server creation failed: %v", err)
	}

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Start()
	}()

	select {
	case startErr := <-startErrCh:
		if startErr == nil {
			t.Fatal("expected Start() to fail when HTTPS bind is blocked")
		}
	case <-time.After(tshttp.DefaultShutdownWait):
		t.Fatal("Start() did not return after HTTPS bind failure")
	}

	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)
	if !waitForNoListener(t, httpAddr, 2*time.Second) {
		t.Fatalf("challenge listener still accepting connections on %s", httpAddr)
	}
}

func TestHTTPSRedirectHandler_IPv6Host(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://[::1]:9080/x?q=1", nil)
	req.Host = "[::1]:9080"
	rec := httptest.NewRecorder()

	newHTTPSRedirectHandler(9443).ServeHTTP(rec, req)

	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", rec.Code)
	}

	if got := rec.Header().Get("Location"); got != "https://[::1]:9443/x?q=1" {
		t.Fatalf("Location = %q, want %q", got, "https://[::1]:9443/x?q=1")
	}
}

// waitForListener polls a TCP address until it accepts or timeout expires.
func waitForListener(t *testing.T, addr string, timeout time.Duration) bool {
	t.Helper()

	dialer := &net.Dialer{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn, err := dialer.DialContext(t.Context(), "tcp", addr)
		if err == nil {
			tshttp.MustClose(t, conn)
			return true
		}

		time.Sleep(50 * time.Millisecond)
	}

	return false
}

func waitForNoListener(t *testing.T, addr string, timeout time.Duration) bool {
	t.Helper()

	dialer := &net.Dialer{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn, err := dialer.DialContext(t.Context(), "tcp", addr)
		if err != nil {
			return true
		}

		tshttp.MustClose(t, conn)
		time.Sleep(50 * time.Millisecond)
	}

	return false
}
