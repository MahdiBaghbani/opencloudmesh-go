// Package harness provides test utilities for integration tests.
package harness

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/httpclient"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/server"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services"

	// Register services (triggers init() registration)
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/loader"
)

// TestServer wraps a server instance for testing.
type TestServer struct {
	Server  *server.Server
	Config  *config.Config
	BaseURL string
	TempDir string
	cancel  context.CancelFunc
}

// StartTestServer creates and starts a test server with dynamic port allocation.
func StartTestServer(t *testing.T) *TestServer {
	t.Helper()

	// Create temp directory for test data
	tempDir, err := os.MkdirTemp("", "ocm-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	// Find a free port
	port, err := getFreePort()
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to find free port: %v", err)
	}

	// Create config - DevConfig() has TLS.Mode="off", SSRFMode="off", InsecureSkipVerify=true
	cfg := config.DevConfig()
	cfg.ListenAddr = fmt.Sprintf(":%d", port)
	cfg.ExternalOrigin = fmt.Sprintf("http://localhost:%d", port)

	// Create logger that discards output (or use t.Log if you want to see logs)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelWarn, // Only log warnings and errors during tests
	}))

	// Create identity components
	partyRepo := identity.NewMemoryPartyRepo()
	sessionRepo := identity.NewMemorySessionRepo()
	userAuth := identity.NewUserAuthFast() // Fast Argon2id params for tests

	// Bootstrap test admin user
	bootstrap := identity.NewBootstrap(partyRepo, userAuth, logger)
	adminUser := identity.SeededUser{
		Username:    "admin",
		Password:    "admin",
		DisplayName: "Test Admin",
		Role:        "admin",
	}
	if _, err := bootstrap.Run(context.Background(), adminUser, nil); err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to bootstrap users: %v", err)
	}

	// Create HTTP client for outbound requests (SSRF off for tests to allow localhost)
	rawHTTPClient := httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode:           "off", // Allow localhost connections in tests
		TimeoutMS:          5000,
		ConnectTimeoutMS:   2000,
		MaxRedirects:       1,
		MaxResponseBytes:   1048576,
		InsecureSkipVerify: true, // For self-signed certs in tests
	})
	httpClient := httpclient.NewContextClient(rawHTTPClient)

	// Create repos for SharedDeps and server.Deps (dual-use)
	incomingShareRepo := shares.NewMemoryIncomingShareRepo()
	outgoingShareRepo := shares.NewMemoryOutgoingShareRepo()
	outgoingInviteRepo := invites.NewMemoryOutgoingInviteRepo()
	incomingInviteRepo := invites.NewMemoryIncomingInviteRepo()
	tokenStore := token.NewMemoryTokenStore()

	// Reset and set SharedDeps for this test (important for test isolation)
	services.ResetDeps()
	services.SetDeps(&services.Deps{
		// Identity
		PartyRepo:   partyRepo,
		SessionRepo: sessionRepo,
		UserAuth:    userAuth,
		// Repos
		IncomingShareRepo:  incomingShareRepo,
		OutgoingShareRepo:  outgoingShareRepo,
		OutgoingInviteRepo: outgoingInviteRepo,
		IncomingInviteRepo: incomingInviteRepo,
		TokenStore:         tokenStore,
		// Clients
		HTTPClient: httpClient,
		// Config
		Config: cfg,
		// KeyManager is nil (no signatures in basic tests)
	})

	// Build wellknown service config using config helpers
	wellknownConfig := cfg.BuildWellknownServiceConfig()

	// Construct wellknown service from registry
	wellknownNew := service.Get("wellknown")
	if wellknownNew == nil {
		os.RemoveAll(tempDir)
		t.Fatalf("wellknown service not registered")
	}
	wellknownSvc, err := wellknownNew(wellknownConfig, logger)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create wellknown service: %v", err)
	}

	// Build OCM service config using config helpers
	ocmConfig := cfg.BuildOCMServiceConfig()
	// Add provider_fqdn for invites handler
	providerFQDN := extractProviderFQDN(cfg.ExternalOrigin)
	ocmConfig["provider_fqdn"] = providerFQDN

	// Construct OCM service from registry
	ocmNew := service.Get("ocm")
	if ocmNew == nil {
		os.RemoveAll(tempDir)
		t.Fatalf("ocm service not registered")
	}
	ocmSvc, err := ocmNew(ocmConfig, logger)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create ocm service: %v", err)
	}

	// Construct ocmaux service from registry
	ocmauxConfig := map[string]any{}
	ocmauxNew := service.Get("ocmaux")
	if ocmauxNew == nil {
		os.RemoveAll(tempDir)
		t.Fatalf("ocmaux service not registered")
	}
	ocmauxSvc, err := ocmauxNew(ocmauxConfig, logger)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create ocmaux service: %v", err)
	}

	// Construct apiservice from registry
	apiserviceConfig := map[string]any{
		"provider_fqdn": providerFQDN,
	}
	apiserviceNew := service.Get("apiservice")
	if apiserviceNew == nil {
		os.RemoveAll(tempDir)
		t.Fatalf("apiservice not registered")
	}
	apiserviceSvc, err := apiserviceNew(apiserviceConfig, logger)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create apiservice: %v", err)
	}

	// Construct uiservice from registry
	uiserviceConfig := map[string]any{
		"external_base_path": cfg.ExternalBasePath,
	}
	uiserviceNew := service.Get("uiservice")
	if uiserviceNew == nil {
		os.RemoveAll(tempDir)
		t.Fatalf("uiservice not registered")
	}
	uiserviceSvc, err := uiserviceNew(uiserviceConfig, logger)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create uiservice: %v", err)
	}

	// Construct webdavservice from registry
	webdavserviceConfig := map[string]any{
		"webdav_token_exchange_mode": cfg.WebDAVTokenExchange.Mode,
	}
	webdavserviceNew := service.Get("webdavservice")
	if webdavserviceNew == nil {
		os.RemoveAll(tempDir)
		t.Fatalf("webdavservice not registered")
	}
	webdavserviceSvc, err := webdavserviceNew(webdavserviceConfig, logger)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create webdavservice: %v", err)
	}

	// Create server (all dependencies come from SharedDeps)
	srv, err := server.New(cfg, logger, wellknownSvc, ocmSvc, ocmauxSvc, apiserviceSvc, uiserviceSvc, webdavserviceSvc)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create server: %v", err)
	}

	// Start server in background
	_, cancel := context.WithCancel(context.Background())

	go func() {
		if err := srv.Start(); err != nil {
			// Server error is expected on shutdown
			_ = err
		}
	}()

	// Wait for server to be ready
	baseURL := fmt.Sprintf("http://localhost:%d", port)
	if err := waitForServer(baseURL, 5*time.Second); err != nil {
		cancel()
		os.RemoveAll(tempDir)
		t.Fatalf("server failed to start: %v", err)
	}

	return &TestServer{
		Server:  srv,
		Config:  cfg,
		BaseURL: baseURL,
		TempDir: tempDir,
		cancel:  cancel,
	}
}

// Stop stops the test server and cleans up resources.
func (ts *TestServer) Stop(t *testing.T) {
	t.Helper()

	ts.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ts.Server.Shutdown(ctx); err != nil {
		t.Logf("warning: shutdown error: %v", err)
	}

	if err := os.RemoveAll(ts.TempDir); err != nil {
		t.Logf("warning: failed to remove temp dir: %v", err)
	}
}

// LogFile returns the path to a log file in the temp directory.
func (ts *TestServer) LogFile(name string) string {
	return filepath.Join(ts.TempDir, name+".log")
}

// getFreePort finds an available TCP port.
func getFreePort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// waitForServer waits for the server to be ready by polling the health endpoint.
func waitForServer(baseURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := net.DialTimeout("tcp", baseURL[7:], 100*time.Millisecond) // strip "http://"
		if err == nil {
			resp.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("server not ready after %v", timeout)
}

// extractProviderFQDN extracts the host:port from an external origin URL.
func extractProviderFQDN(externalOrigin string) string {
	// Remove scheme
	fqdn := externalOrigin
	if idx := len("https://"); len(fqdn) > idx && fqdn[:idx] == "https://" {
		fqdn = fqdn[idx:]
	} else if idx := len("http://"); len(fqdn) > idx && fqdn[:idx] == "http://" {
		fqdn = fqdn[idx:]
	}
	// Remove trailing slash
	if len(fqdn) > 0 && fqdn[len(fqdn)-1] == '/' {
		fqdn = fqdn[:len(fqdn)-1]
	}
	return fqdn
}
