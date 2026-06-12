package wiring_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestCryptoParity_SkipCryptoGatesDeps(t *testing.T) {
	t.Run("SkipCrypto=true produces nil crypto deps", func(t *testing.T) {
		cfg := wiringtest.DevConfigHarness(18082)

		deps.ResetDeps()
		_, err := wiring.Build(cfg, wiringtest.DiscardLogger(), wiringtest.HarnessWireOptions())
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := deps.GetDeps()
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

		deps.ResetDeps()
		opts := wiringtest.HarnessWireOptions()
		opts.SkipCrypto = false
		_, err := wiring.Build(cfg, wiringtest.DiscardLogger(), opts)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := deps.GetDeps()
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
}
