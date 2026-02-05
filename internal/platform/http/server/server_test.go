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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
)

// trackingService is a test service that records when Close() is called.
type trackingService struct {
	name       string
	prefix     string
	closeOrder *[]string
}

func (t *trackingService) Handler() http.Handler { return http.NotFoundHandler() }
func (t *trackingService) Prefix() string        { return t.prefix }
func (t *trackingService) Unprotected() []string  { return nil }
func (t *trackingService) Close() error {
	*t.closeOrder = append(*t.closeOrder, t.name)
	return nil
}

// setupTestSharedDeps sets up SharedDeps for testing and returns a cleanup function.
func setupTestSharedDeps(t *testing.T) func() {
	t.Helper()
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		PartyRepo:   identity.NewMemoryPartyRepo(),
		SessionRepo: identity.NewMemorySessionRepo(),
		UserAuth:    identity.NewUserAuth(1),
		HTTPClient:  httpclient.NewContextClient(httpclient.New(nil, nil)),
	})
	return func() {
		deps.ResetDeps()
	}
}

func TestNew_FailsWithNilSharedDeps(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Ensure SharedDeps is nil
	deps.ResetDeps()
	defer deps.ResetDeps()

	_, err := New(cfg, logger, nil)
	if err == nil {
		t.Fatal("expected error for nil SharedDeps")
	}
	if !errors.Is(err, ErrMissingSharedDeps) {
		t.Errorf("expected ErrMissingSharedDeps, got: %v", err)
	}
}

func TestNew_SucceedsWithSharedDeps(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cleanup := setupTestSharedDeps(t)
	defer cleanup()

	srv, err := New(cfg, logger, nil) // nil service map acceptable for tests
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

	cleanup := setupTestSharedDeps(t)
	defer cleanup()

	// Track close order
	var closeOrder []string

	// Create tracking services
	svc1 := &trackingService{name: "svc1", prefix: "svc1", closeOrder: &closeOrder}
	svc2 := &trackingService{name: "svc2", prefix: "svc2", closeOrder: &closeOrder}
	svc3 := &trackingService{name: "svc3", prefix: "svc3", closeOrder: &closeOrder}

	// Create server with services in map (mount order: ocmaux, api, ui)
	srv, err := New(cfg, logger, map[string]service.Service{
		"ocmaux": svc1,
		"api":    svc2,
		"ui":     svc3,
	})
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
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("getFreePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// generateTestCert creates a self-signed cert+key pair and writes them as
// cert.pem and key.pem in dir. Returns the paths.
func generateTestCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
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
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
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

	cleanup := setupTestSharedDeps(t)
	defer cleanup()

	srv, err := New(cfg, logger, nil)
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

	// 1. Challenge handler returns 404 for unknown token.
	resp, err := http.Get(fmt.Sprintf("http://%s/.well-known/acme-challenge/nonexistent", httpAddr))
	if err != nil {
		t.Fatalf("challenge request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for unknown challenge token, got %d", resp.StatusCode)
	}

	// 2. Non-challenge HTTP request returns 308 redirect to HTTPS.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // do not follow redirects
	}}
	resp, err = client.Get(fmt.Sprintf("http://%s/some/path?q=1", httpAddr))
	if err != nil {
		t.Fatalf("redirect request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("expected 308, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	expected := fmt.Sprintf("https://127.0.0.1:%d/some/path?q=1", httpsPort)
	if loc != expected {
		t.Errorf("redirect Location = %q, want %q", loc, expected)
	}

	// 3. HTTPS listener serves with the loaded certificate.
	tlsClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &cryptotls.Config{InsecureSkipVerify: true},
	}}
	resp, err = tlsClient.Get(fmt.Sprintf("https://%s/", httpsAddr))
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	resp.Body.Close()
	// Any response means the TLS handshake and listener work; the actual
	// status depends on mounted services (404 is fine with nil service map).
	if resp.TLS == nil {
		t.Error("expected TLS connection info, got nil")
	}

	// 4. Clean shutdown.
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
	case <-time.After(5 * time.Second):
		t.Error("Start() did not return after shutdown")
	}
}

func TestACME_MissingPorts(t *testing.T) {
	cfg := config.DevConfig()
	cfg.TLS.Mode = "acme"
	cfg.ListenAddr = "127.0.0.1:0"

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cleanup := setupTestSharedDeps(t)
	defer cleanup()

	// HTTPPort = 0
	cfg.TLS.HTTPPort = 0
	cfg.TLS.HTTPSPort = 9443
	srv, err := New(cfg, logger, nil)
	if err != nil {
		t.Fatalf("server creation failed: %v", err)
	}
	if err := srv.Start(); err == nil {
		t.Error("expected error for zero HTTPPort")
	}

	// HTTPSPort = 0
	cfg.TLS.HTTPPort = 9080
	cfg.TLS.HTTPSPort = 0
	srv, err = New(cfg, logger, nil)
	if err != nil {
		t.Fatalf("server creation failed: %v", err)
	}
	if err := srv.Start(); err == nil {
		t.Error("expected error for zero HTTPSPort")
	}
}

// waitForListener polls a TCP address until it accepts or timeout expires.
func waitForListener(t *testing.T, addr string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
