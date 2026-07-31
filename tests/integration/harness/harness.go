// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/server"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	// Register cache drivers
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

// TestServer wraps a server instance for testing.
type TestServer struct {
	Server      *server.Server
	Config      *config.Config
	BaseURL     string
	TempDir     string
	Deps        *wiring.Deps
	persistence *repos.Repos
	once        sync.Once
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
	return startTestServer(t, patch, IntegrationBuildOpts())
}

// StartTestServerWithOutgoingSharePolicy starts a test server with outbound
// signing policy and keys wired for outgoing share consumer integration tests.
func StartTestServerWithOutgoingSharePolicy(t *testing.T, patch func(*config.Config)) *TestServer {
	t.Helper()
	return startTestServer(t, patch, OutgoingSharePolicyBuildOpts())
}

// StartTestServerWithIETFConfig starts a test server with real signing keys and
// inbound signature middleware enabled. Use for HTTP signature integration tests.
func StartTestServerWithIETFConfig(t *testing.T, patch func(*config.Config)) *TestServer {
	t.Helper()

	return startTestServer(t, func(cfg *config.Config) {
		applyIETFConfigDefaults(cfg)

		if patch != nil {
			patch(cfg)
		}
	}, IETFIntegrationBuildOpts())
}

// applyIETFConfigDefaults is a hybrid overlay on DevConfig(): it sets the
// signature label used by the IETF integration harness. Other DevConfig
// leniencies (TLS off, SSRF off, insecure_skip_verify) are intentionally
// preserved.
func applyIETFConfigDefaults(cfg *config.Config) {
	cfg.Signature.Label = config.DefaultSignatureLabel
}

func startTestServer(t *testing.T, patch func(*config.Config), buildOpts wiring.BuildOpts) *TestServer {
	t.Helper()

	// Create temp directory for test data
	tempDir, err := os.MkdirTemp("", "ocm-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	// Find a free port
	port, err := getFreePort(t.Context())
	if err != nil {
		//nolint:errcheck // test cleanup: best-effort temp dir removal
		os.RemoveAll(tempDir)
		t.Fatalf("failed to find free port: %v", err)
	}

	// Create config - DevConfig() has TLS.Mode="off", SSRF.Mode="off", InsecureSkipVerify=true
	cfg := config.DevConfig()
	cfg.ListenAddr = fmt.Sprintf(":%d", port)
	cfg.PublicOrigin = fmt.Sprintf("http://localhost:%d", port)
	cfg.Signature.KeyPath = filepath.Join(tempDir, "keys", "signing.pem")

	if patch != nil {
		patch(cfg)
	}

	// Fail-fast checks that must run before any side-effecting bootstrap
	// (mirrors main.go: impossible startup state must never cause partial startup).
	if validateErr := validatePreBootstrapStartup(cfg); validateErr != nil {
		//nolint:errcheck // test cleanup: best-effort temp dir removal
		os.RemoveAll(tempDir)
		t.Fatalf("pre-bootstrap startup validation rejected: %v", validateErr)
	}

	// Logger writes warnings and errors to stdout for test diagnostics.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))

	// Wire via wiring.Build using the caller-selected harness build options.
	buildResult, err := wiring.Build(cfg, logger, buildOpts)
	if err != nil {
		//nolint:errcheck // test cleanup: best-effort temp dir removal
		os.RemoveAll(tempDir)
		t.Fatalf("failed to bootstrap dependencies: %v", err)
	}

	d := buildResult.Deps
	if d == nil {
		//nolint:errcheck // test cleanup: best-effort temp dir removal
		os.RemoveAll(tempDir)
		t.Fatal(wiring.ErrMsgNilDepsAfterBuild)
	}

	bootstrap := identity.NewBootstrap(d.PartyRepo, d.UserAuth, logger)

	adminUser := identity.SeededUser{
		Username:    "admin",
		Password:    "admin",
		DisplayName: "Test Admin",
		Role:        "admin",
	}
	if _, bootstrapErr := bootstrap.Run(context.Background(), adminUser, nil); bootstrapErr != nil {
		//nolint:errcheck // test cleanup: best-effort temp dir removal
		os.RemoveAll(tempDir)
		t.Fatalf("failed to bootstrap users: %v", bootstrapErr)
	}

	services, err := wiring.BuildCoreServices(cfg, logger, d)
	if err != nil {
		//nolint:errcheck // test cleanup: best-effort temp dir removal
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create core services: %v", err)
	}

	if validateErr := service.ValidateBuiltServices(services); validateErr != nil {
		//nolint:errcheck // test cleanup: best-effort temp dir removal
		os.RemoveAll(tempDir)
		t.Fatalf("built service validation rejected: %v", validateErr)
	}

	serverDeps, err := wiring.BuildServerDeps(cfg, logger, d)
	if err != nil {
		//nolint:errcheck // test cleanup: best-effort temp dir removal
		os.RemoveAll(tempDir)
		t.Fatalf("failed to build server deps: %v", err)
	}

	srv, err := server.New(cfg, logger, services, serverDeps)
	if err != nil {
		//nolint:errcheck // test cleanup: best-effort temp dir removal
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create server: %v", err)
	}

	srv.SetRootCAPool(buildResult.RootCAPool)

	// Start server in background
	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server startup/runtime error", "error", err)
		}
	}()

	// BaseURL is the real local request target: localhost on the allocated
	// listener port using the actual listener scheme. It is deliberately derived
	// from the listener, not cfg.PublicOrigin, because tests may patch
	// PublicOrigin to exercise advertised-origin behavior while the server still
	// listens on the ephemeral ListenAddr port.
	baseURL := localListenerBaseURL(cfg.TLS.Mode, port)
	// App endpoints (including /api/healthz) mount under ExternalBasePath when
	// set, so the readiness probe must target that path, not bare root.
	if err := waitForServerReady(t.Context(), healthEndpointURL(baseURL, cfg.ExternalBasePath), 5*time.Second); err != nil {
		//nolint:errcheck // test cleanup: best-effort temp dir removal
		os.RemoveAll(tempDir)
		t.Fatalf("server failed to start: %v", err)
	}

	ts := &TestServer{
		Server:      srv,
		Config:      cfg,
		BaseURL:     baseURL,
		TempDir:     tempDir,
		Deps:        d,
		persistence: buildResult.Persistence,
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

		if ts.persistence != nil {
			if err := ts.persistence.Close(); err != nil {
				t.Logf("warning: persistence close error: %v", err)
			}
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

// validatePreBootstrapStartup runs the fail-fast checks that the real binary
// applies before any side-effecting bootstrap. It returns an error (rather than
// calling t.Fatalf) so it can be unit-tested directly.
func validatePreBootstrapStartup(cfg *config.Config) error {
	return service.ValidatePreBootstrap(cfg)
}

// localListenerScheme returns the scheme the in-process test server actually
// listens with. It mirrors server.Start: TLS mode "off" serves plain HTTP and
// any other mode serves HTTPS. This is intentionally independent of
// cfg.PublicOrigin, which is only the advertised origin and may be patched by
// tests.
func localListenerScheme(tlsMode string) string {
	if strings.TrimSpace(tlsMode) == "off" {
		return "http"
	}

	return "https"
}

// localListenerBaseURL builds the real request target for in-process test
// traffic: localhost on the allocated listener port using the actual listener
// scheme. It ignores cfg.PublicOrigin so advertised-origin patches do not break
// local readiness probing or test requests.
func localListenerBaseURL(tlsMode string, port int) string {
	return fmt.Sprintf("%s://localhost:%d", localListenerScheme(tlsMode), port)
}

// getFreePort finds an available TCP port.
func getFreePort(ctx context.Context) (int, error) {
	// integration test harness: intentional bind for test network
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", ":0")
	if err != nil {
		return 0, err
	}
	//nolint:errcheck // test cleanup: ephemeral listener close
	defer listener.Close()

	//nolint:errcheck // test helper: ephemeral TCP listener address
	return listener.Addr().(*net.TCPAddr).Port, nil //nolint:forcetypeassert // test: TCPAddr assertion is safe for net.Listen TCP listener
}
