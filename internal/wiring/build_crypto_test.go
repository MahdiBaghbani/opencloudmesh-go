package wiring_test

import (
	tscfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/cfg"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestCryptoSkip_GatesDeps(t *testing.T) {
	t.Run("SkipCrypto=true produces nil crypto deps", func(t *testing.T) {
		cfg := tscfg.DevConfigHarness(18082)

		result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
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
		cfg := tscfg.DevConfigNoSignatures(18083)

		opts := harnessBuildOpts()
		opts.SkipCrypto = false
		result, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
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
		cfg := tscfg.DevConfigHarness(18084)

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
