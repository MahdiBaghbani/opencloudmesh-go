package wiring_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestSignatureMiddlewareParity_SkipGatesConstruction(t *testing.T) {
	t.Run("SkipSignatureMiddleware=true produces nil middleware", func(t *testing.T) {
		deps.ResetDeps()
		_, err := wiring.Build(
			wiringtest.DevConfigNoSignatures(18086),
			wiringtest.DiscardLogger(),
			wiringtest.HarnessWireOptions(),
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		if deps.GetDeps().SignatureMiddleware != nil {
			t.Error("SignatureMiddleware must be nil when SkipSignatureMiddleware=true")
		}
	})

	t.Run("SkipSignatureMiddleware=false produces non-nil middleware", func(t *testing.T) {
		deps.ResetDeps()
		opts := wiringtest.HarnessWireOptions()
		opts.SkipSignatureMiddleware = false
		_, err := wiring.Build(
			wiringtest.DevConfigNoSignatures(18087),
			wiringtest.DiscardLogger(),
			opts,
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		if deps.GetDeps().SignatureMiddleware == nil {
			t.Error("SignatureMiddleware must be non-nil when SkipSignatureMiddleware=false")
		}
	})
}
