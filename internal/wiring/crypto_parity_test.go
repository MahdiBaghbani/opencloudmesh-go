package wiring_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestCryptoParity_SkipCryptoGatesDeps(t *testing.T) {
	t.Run("SkipCrypto=true produces nil crypto deps", func(t *testing.T) {
		cfg := wiringtest.DevConfigHarness(18082)

		result, err := wiring.Build(cfg, wiringtest.DiscardLogger(), harnessBuildOpts())
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
		if d.OutboundPolicy != nil {
			t.Error("OutboundPolicy must be nil when SkipCrypto=true")
		}
	})

	t.Run("SkipCrypto=false with signature modes off produces non-nil OutboundPolicy", func(t *testing.T) {
		cfg := wiringtest.DevConfigNoSignatures(18083)

		opts := harnessBuildOpts()
		opts.SkipCrypto = false
		result, err := wiring.Build(cfg, wiringtest.DiscardLogger(), opts)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := result.Deps
		if d.KeyManager != nil {
			t.Error("KeyManager must be nil when both signature modes are off")
		}
		if d.Signer != nil {
			t.Error("Signer must be nil when KeyManager is nil")
		}
		if d.OutboundPolicy == nil {
			t.Error("OutboundPolicy must be non-nil when SkipCrypto=false")
		}
	})

	t.Run("SkipCrypto=false with signature modes on produces non-nil Signer", func(t *testing.T) {
		cfg := wiringtest.DevConfigHarness(18084)

		opts := harnessBuildOpts()
		opts.SkipCrypto = false
		result, err := wiring.Build(cfg, wiringtest.DiscardLogger(), opts)
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
