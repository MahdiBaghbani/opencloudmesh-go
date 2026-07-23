package wiring_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	tswiring "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestCryptoSkip_GatesDeps(t *testing.T) {
	t.Run("SkipCrypto=true fails when code flow requires HTTP signatures", func(t *testing.T) {
		cfg := config.DevConfig()

		opts := harnessBuildOpts()
		opts.SkipCrypto = true
		_, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
		if err == nil {
			t.Fatal("expected bootstrap to fail when SkipCrypto=true and code flow requires HTTP signatures")
		}
		want := "ocm: code flow requires HTTP request signatures but no signing key is configured"
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err.Error(), want)
		}
	})

	t.Run("SkipCrypto=true succeeds when code flow does not require HTTP signatures", func(t *testing.T) {
		cfg := config.DevConfig()
		falseVal := false
		cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures = &falseVal

		opts := harnessBuildOpts()
		opts.SkipCrypto = true
		result, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
		if err != nil {
			t.Fatalf("bootstrap should succeed when requires_http_request_signatures=false and SkipCrypto=true: %v", err)
		}
		if result.Deps == nil {
			t.Fatal("Deps is nil after successful Build")
		}
		if result.Deps.CodeFlow == nil {
			t.Fatal("CodeFlow is nil; Build must populate it")
		}
		if facts := result.Deps.CodeFlow.Evaluate(); facts.RequiresHTTPRequestSignatures {
			t.Error("expected CodeFlow.Evaluate() to report RequiresHTTPRequestSignatures=false")
		}
	})

	t.Run("SkipCrypto=false with crypto enabled produces non-nil Signer", func(t *testing.T) {
		cfg := config.DevConfig()

		opts := harnessBuildOpts()
		opts.SkipCrypto = false
		result, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := result.Deps
		if d.KeyManager == nil {
			t.Error("KeyManager must be non-nil when crypto is enabled and SkipCrypto=false")
		}
		if d.Signer == nil {
			t.Error("Signer must be non-nil when KeyManager is present")
		}
	})
}

func TestBuild_SignatureConfigWiresSignerOptions(t *testing.T) {
	cfg := config.DevConfig()
	cfg.Signature.Label = "wiredlabel"

	opts := harnessBuildOpts()
	opts.SkipCrypto = false

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	if result.Deps.Signer == nil {
		t.Fatal("Signer must be non-nil when crypto is enabled")
	}

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"

	if err := result.Deps.Signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	if !strings.HasPrefix(sigInput, "wiredlabel=") {
		t.Fatalf("Signature-Input = %q, want wiredlabel= prefix from config", sigInput)
	}
}

func TestBuild_IETFHarnessOptsWireFullCryptoStack(t *testing.T) {
	cfg := config.DevConfig()

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), toBuildOpts(tswiring.IETFWireOptions))
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	if result.Deps.KeyManager == nil {
		t.Fatal("KeyManager must be non-nil for IETF harness opts")
	}
	if result.Deps.Signer == nil {
		t.Fatal("Signer must be non-nil for IETF harness opts")
	}
	if result.Deps.SignatureMiddleware == nil {
		t.Fatal("SignatureMiddleware must be non-nil for IETF harness opts")
	}
}
