package wiring_test

import (
	tscfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/cfg"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	tswiring "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/wiring"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestSignatureMiddlewareSkip_GatesConstruction(t *testing.T) {
	t.Run("SkipSignatureMiddleware=true produces nil middleware", func(t *testing.T) {
		result, err := wiring.Build(
			tscfg.DevConfigNoSignatures(18086),
			tslog.DiscardLogger(),
			harnessBuildOpts(),
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		if result.Deps.SignatureMiddleware != nil {
			t.Error("SignatureMiddleware must be nil when SkipSignatureMiddleware=true")
		}
	})

	t.Run("SkipSignatureMiddleware=false produces non-nil middleware", func(t *testing.T) {
		opts := harnessBuildOpts()
		opts.SkipSignatureMiddleware = false
		opts.SkipCrypto = false
		result, err := wiring.Build(
			tscfg.DevConfigNoSignatures(18087),
			tslog.DiscardLogger(),
			opts,
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		if result.Deps.SignatureMiddleware == nil {
			t.Error("SignatureMiddleware must be non-nil when SkipSignatureMiddleware=false")
		}
	})

	t.Run("IETF harness opts produce non-nil middleware with signing keys", func(t *testing.T) {
		result, err := wiring.Build(
			tscfg.DevConfigHarness(18090),
			tslog.DiscardLogger(),
			toBuildOpts(tswiring.IETFWireOptions),
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		if result.Deps.KeyManager == nil {
			t.Error("KeyManager must be non-nil for IETF harness opts")
		}
		if result.Deps.SignatureMiddleware == nil {
			t.Error("SignatureMiddleware must be non-nil for IETF harness opts")
		}
	})
}
