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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/httpclient"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/server"
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
		IncomingShareRepo:  incomingShareRepo,
		OutgoingShareRepo:  outgoingShareRepo,
		OutgoingInviteRepo: outgoingInviteRepo,
		IncomingInviteRepo: incomingInviteRepo,
		TokenStore:         tokenStore,
		HTTPClient:         httpClient,
		// KeyManager is nil (no signatures in basic tests)
	})

	// Compute token exchange enabled from config
	isTokenExchangeEnabled := cfg.TokenExchange.Enabled != nil && *cfg.TokenExchange.Enabled

	// Build wellknown service config
	wellknownConfig := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint":    cfg.ExternalOrigin + cfg.ExternalBasePath,
			"ocm_prefix":  "ocm",
			"provider":    "OpenCloudMesh",
			"webdav_root": cfg.ExternalBasePath + "/webdav/ocm/",
			"advertise_http_request_signatures": cfg.Signature.AdvertiseHTTPRequestSignatures,
			"token_exchange": map[string]any{
				"enabled": isTokenExchangeEnabled,
				"path":    cfg.TokenExchange.Path,
			},
		},
	}

	// Construct wellknown service from registry
	wellknownNew := services.Get("wellknown")
	if wellknownNew == nil {
		os.RemoveAll(tempDir)
		t.Fatalf("wellknown service not registered")
	}
	wellknownSvc, err := wellknownNew(wellknownConfig, logger)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create wellknown service: %v", err)
	}

	// Create server dependencies
	deps := &server.Deps{
		PartyRepo:          partyRepo,
		SessionRepo:        sessionRepo,
		UserAuth:           userAuth,
		HTTPClient:         httpClient,
		IncomingShareRepo:  incomingShareRepo,
		OutgoingShareRepo:  outgoingShareRepo,
		OutgoingInviteRepo: outgoingInviteRepo,
		IncomingInviteRepo: incomingInviteRepo,
		TokenStore:         tokenStore,
	}

	// Create server
	srv, err := server.New(cfg, logger, deps, wellknownSvc)
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
