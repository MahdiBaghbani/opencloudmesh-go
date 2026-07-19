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
	t.Run("SkipCrypto=true produces nil crypto deps", func(t *testing.T) {
		cfg := config.DevConfig()

		opts := harnessBuildOpts()
		opts.SkipCrypto = true
		result, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := result.Deps
		if d.KeyManager != nil {
			t.Error("KeyManager must be nil when SkipCrypto=true")
		}
		if d.Signer != nil {
			t.Error("Signer must be nil when SkipCrypto=true")
		}
	})

	t.Run("SkipCrypto=false with signature modes on produces non-nil Signer", func(t *testing.T) {
		cfg := config.DevConfig()

		opts := harnessBuildOpts()
		opts.SkipCrypto = false
		result, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := result.Deps
		if d.KeyManager == nil {
			t.Error("KeyManager must be non-nil when signature modes are on and SkipCrypto=false")
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
		t.Fatal("Signer must be non-nil when signature modes are on")
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
