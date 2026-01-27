package tls_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tlspkg "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/tls"
)

func TestTLSManager_Off(t *testing.T) {
	cfg := &config.TLSConfig{Mode: "off"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := tlspkg.NewTLSManager(cfg, logger)

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
	mgr := tlspkg.NewTLSManager(cfg, logger)

	_, err := mgr.GetTLSConfig("localhost")
	if err != tlspkg.ErrMissingCert {
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
	mgr := tlspkg.NewTLSManager(cfg, logger)

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
	mgr := tlspkg.NewTLSManager(cfg, logger)

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
	mgr := tlspkg.NewTLSManager(cfg, logger)

	_, err := mgr.GetTLSConfig("localhost")
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}
