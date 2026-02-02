// Package harness provides test utilities for integration tests.
package harness

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/instanceid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/server"

	// Register cache drivers
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"

	// Register interceptors (triggers init() registration)
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/loader"

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
	cfg.PublicOrigin = fmt.Sprintf("http://localhost:%d", port)

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
	outgoingShareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	outgoingInviteRepo := invites.NewMemoryOutgoingInviteRepo()
	incomingInviteRepo := invites.NewMemoryIncomingInviteRepo()
	tokenStore := token.NewMemoryTokenStore()

	// Create memory cache for tests (required for rate limiting interceptor)
	cacheInstance := cache.NewDefault()

	// Create RealIP extractor for trusted-proxy-aware client identity
	realIPExtractor := realip.NewTrustedProxies(cfg.Server.TrustedProxies)

	// Derive local provider identity from PublicOrigin
	localProviderFQDN, err := instanceid.ProviderFQDN(cfg.PublicOrigin)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to derive provider FQDN: %v", err)
	}
	localProviderFQDNForCompare, err := hostport.Normalize(localProviderFQDN, cfg.PublicScheme())
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to normalize provider FQDN: %v", err)
	}

	// Reset and set SharedDeps for this test (important for test isolation)
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
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
		// Provider identity
		LocalProviderFQDN:           localProviderFQDN,
		LocalProviderFQDNForCompare: localProviderFQDNForCompare,
		// Config
		Config: cfg,
		// Cache (for interceptors like rate limiting)
		Cache: cacheInstance,
		// RealIP (for trusted-proxy-aware client identity)
		RealIP: realIPExtractor,
		// KeyManager is nil (no signatures in basic tests)
	})

	// Validate [http.services.*] keys (mirrors main.go fail-fast)
	if cfg.HTTP.Services != nil {
		allowed := service.RegisteredServices()
		allowedSet := make(map[string]struct{}, len(allowed))
		for _, name := range allowed {
			allowedSet[name] = struct{}{}
		}

		var unknown []string
		for name := range cfg.HTTP.Services {
			if _, ok := allowedSet[name]; !ok {
				unknown = append(unknown, name)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			sort.Strings(allowed)
			os.RemoveAll(tempDir)
			t.Fatalf("unknown service names in [http.services]: %s (allowed: %s)",
				strings.Join(unknown, ", "), strings.Join(allowed, ", "))
		}
	}

	// Construct all core services via registry loop (mirrors main.go).
	// Each service derives cross-cutting values from SharedDeps internally.
	services := make(map[string]service.Service)
	for _, name := range service.CoreServices {
		svcCfg := cfg.BuildServiceConfig(name)
		if svcCfg == nil {
			svcCfg = make(map[string]any)
		}
		newFn := service.Get(name)
		if newFn == nil {
			os.RemoveAll(tempDir)
			t.Fatalf("core service %q not registered", name)
		}
		svc, err := newFn(svcCfg, logger)
		if err != nil {
			os.RemoveAll(tempDir)
			t.Fatalf("failed to create %s service: %v", name, err)
		}
		services[name] = svc
	}

	srv, err := server.New(cfg, logger, services)
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

