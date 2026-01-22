package server_test

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/httpclient"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/server"
)

// setupTestSharedDeps sets up SharedDeps for testing and returns a cleanup function.
func setupTestSharedDeps(t *testing.T) func() {
	t.Helper()
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		PartyRepo:   identity.NewMemoryPartyRepo(),
		SessionRepo: identity.NewMemorySessionRepo(),
		UserAuth:    identity.NewUserAuth(1),
		HTTPClient:  httpclient.NewContextClient(httpclient.New(nil)),
	})
	return func() {
		deps.ResetDeps()
	}
}

func TestTLSManager_Off(t *testing.T) {
	cfg := &config.TLSConfig{Mode: "off"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := server.NewTLSManager(cfg, logger)

	tlsCfg, err := mgr.GetTLSConfig("localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg != nil {
		t.Error("expected nil TLS config for 'off' mode")
	}
}

func TestTLSManager_Static_MissingFiles(t *testing.T) {
	cfg := &config.TLSConfig{
		Mode:     "static",
		CertFile: "",
		KeyFile:  "",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := server.NewTLSManager(cfg, logger)

	_, err := mgr.GetTLSConfig("localhost")
	if err != server.ErrMissingCert {
		t.Errorf("expected ErrMissingCert, got %v", err)
	}
}

func TestTLSManager_SelfSigned_Generate(t *testing.T) {
	// Create temp directory for certs
	tempDir, err := os.MkdirTemp("", "ocm-test-tls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.TLSConfig{
		Mode:          "selfsigned",
		SelfSignedDir: tempDir,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := server.NewTLSManager(cfg, logger)

	tlsCfg, err := mgr.GetTLSConfig("localhost")
	if err != nil {
		t.Fatalf("GetTLSConfig failed: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if len(tlsCfg.Certificates) == 0 {
		t.Error("expected at least one certificate")
	}

	// Verify files were created
	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Error("certificate file not created")
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Error("key file not created")
	}
}

func TestTLSManager_SelfSigned_Reload(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ocm-test-tls-reload-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.TLSConfig{
		Mode:          "selfsigned",
		SelfSignedDir: tempDir,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := server.NewTLSManager(cfg, logger)

	// First call generates cert
	tlsCfg1, err := mgr.GetTLSConfig("localhost")
	if err != nil {
		t.Fatalf("first GetTLSConfig failed: %v", err)
	}

	// Second call should load existing cert
	tlsCfg2, err := mgr.GetTLSConfig("localhost")
	if err != nil {
		t.Fatalf("second GetTLSConfig failed: %v", err)
	}

	// Both should have certificates
	if len(tlsCfg1.Certificates) == 0 || len(tlsCfg2.Certificates) == 0 {
		t.Error("expected certificates in both configs")
	}
}

func TestTLSManager_InvalidMode(t *testing.T) {
	cfg := &config.TLSConfig{Mode: "invalid"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := server.NewTLSManager(cfg, logger)

	_, err := mgr.GetTLSConfig("localhost")
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestTLSManager_ACME_FailFast(t *testing.T) {
	// ACME mode should fail fast when Server.Start() is called
	// The TLSManager itself returns a placeholder config, but Server.Start()
	// should detect acme mode and return ErrACMENotImplemented
	cfg := config.DevConfig()
	cfg.TLS.Mode = "acme"
	cfg.ListenAddr = ":0" // Dynamic port

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cleanup := setupTestSharedDeps(t)
	defer cleanup()

	srv, err := server.New(cfg, logger, nil, nil, nil, nil, nil, nil) // nil services acceptable for this test
	if err != nil {
		t.Fatalf("server creation failed: %v", err)
	}

	// Start should fail fast with ACME error
	err = srv.Start()
	if !errors.Is(err, server.ErrACMENotImplemented) {
		t.Errorf("expected ErrACMENotImplemented, got %v", err)
	}
}
