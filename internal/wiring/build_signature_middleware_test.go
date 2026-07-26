package wiring_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	tswiring "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestSignatureMiddleware_AlwaysConstructed(t *testing.T) {
	t.Run("harness opts produce non-nil middleware", func(t *testing.T) {
		opts := harnessBuildOpts()
		opts.SkipCrypto = false

		result, err := wiring.Build(
			config.DevConfig(),
			tslog.DiscardLogger(),
			opts,
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}

		if result.Deps.SignatureMiddleware == nil {
			t.Error("SignatureMiddleware must be non-nil")
		}
	})

	t.Run("IETF harness opts produce non-nil middleware with signing keys", func(t *testing.T) {
		result, err := wiring.Build(
			config.DevConfig(),
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
