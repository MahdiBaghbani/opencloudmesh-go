package wiring_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestSignatureMiddlewareParity_SkipGatesConstruction(t *testing.T) {
	t.Run("SkipSignatureMiddleware=true produces nil middleware", func(t *testing.T) {
		result, err := wiring.Build(
			wiringtest.DevConfigNoSignatures(18086),
			wiringtest.DiscardLogger(),
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
		result, err := wiring.Build(
			wiringtest.DevConfigNoSignatures(18087),
			wiringtest.DiscardLogger(),
			opts,
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		if result.Deps.SignatureMiddleware == nil {
			t.Error("SignatureMiddleware must be non-nil when SkipSignatureMiddleware=false")
		}
	})
}
