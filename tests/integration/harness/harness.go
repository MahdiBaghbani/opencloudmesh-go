// Package harness provides test utilities for integration tests.
package harness

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/app"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
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
	once    sync.Once
}

// StartTestServer creates and starts a test server with dynamic port allocation.
func StartTestServer(t *testing.T) *TestServer {
	t.Helper()
	return StartTestServerWithConfig(t, nil)
}

// StartTestServerWithConfig creates and starts a test server, applying an
// optional patch function to the config before startup. Use this when tests
// need a specific policy or config setting at server-creation time.
func StartTestServerWithConfig(t *testing.T, patch func(*config.Config)) *TestServer {
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

	if patch != nil {
		patch(cfg)
	}

	// Validate [http.services.*] keys before any side-effecting bootstrap
	// (mirrors main.go fail-fast: a typo must never cause partial startup).
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

	// Logger writes warnings and errors to stdout for test diagnostics.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))

	// Reset shared deps for test isolation, then wire via BootstrapDeps.
	// WireOptions reflects the intended harness defaults:
	//   - FastAuth: low-cost argon2id for test speed
	//   - SkipCrypto: no signing keys; avoids leaking production crypto into tests
	//   - SkipPeerTrust: peer trust stack is not exercised in in-process tests
	//   - SkipSignatureMiddleware: inbound signature verification skipped
	//   - OutboundOverride: permissive localhost-friendly outbound config
	//   - SkipDiscoveryCache: no-op cache avoids stale cross-test discovery entries
	deps.ResetDeps()
	bootstrapResult, err := app.BootstrapDeps(cfg, logger, app.WireOptions{
		FastAuth:                true,
		SkipCrypto:              true,
		SkipPeerTrust:           true,
		SkipSignatureMiddleware: true,
		OutboundOverride: &config.OutboundHTTPConfig{
			SSRF:               config.SSRFConfig{Mode: "off"}, // Allow localhost connections in tests
			SSRFMode:           "off",
			TimeoutMS:          5000,
			ConnectTimeoutMS:   2000,
			MaxRedirects:       1,
			MaxResponseBytes:   1048576,
			InsecureSkipVerify: true, // For self-signed certs in tests
		},
		SkipDiscoveryCache: true,
	})
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to bootstrap dependencies: %v", err)
	}

	// Bootstrap test admin user
	d := deps.GetDeps()
	if d == nil {
		os.RemoveAll(tempDir)
		t.Fatalf("BootstrapDeps succeeded but deps are nil; this is a bug in BootstrapDeps")
	}
	bootstrap := identity.NewBootstrap(d.PartyRepo, d.UserAuth, logger)
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
	srv.SetRootCAPool(bootstrapResult.RootCAPool)

	// Start server in background
	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server startup/runtime error", "error", err)
		}
	}()

	// Derive baseURL from the patched config.PublicOrigin so that any patch
	// that changes the scheme or host is reflected correctly here and in TestServer.
	baseURL := strings.TrimSuffix(cfg.PublicOrigin, "/")
	if err := waitForServerReady(baseURL, 5*time.Second); err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("server failed to start: %v", err)
	}

	ts := &TestServer{
		Server:  srv,
		Config:  cfg,
		BaseURL: baseURL,
		TempDir: tempDir,
	}
	t.Cleanup(func() { ts.Stop(t) })
	return ts
}

// Stop stops the test server and cleans up resources. Safe to call more than
// once; the second and subsequent calls are no-ops.
func (ts *TestServer) Stop(t *testing.T) {
	t.Helper()
	ts.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := ts.Server.Shutdown(ctx); err != nil {
			t.Logf("warning: shutdown error: %v", err)
		}

		if err := os.RemoveAll(ts.TempDir); err != nil {
			t.Logf("warning: failed to remove temp dir: %v", err)
		}
	})
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
