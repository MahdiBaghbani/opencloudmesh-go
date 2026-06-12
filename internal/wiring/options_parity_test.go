package wiring_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestOptionsParity_HarnessOptionsBootstrapSucceeds(t *testing.T) {
	cfg := wiringtest.DevConfigHarness(18080)

	deps.ResetDeps()

	result, err := wiring.Build(cfg, wiringtest.DiscardLogger(), wiringtest.HarnessWireOptions())
	if err != nil {
		t.Fatalf("Build with harness options failed: %v", err)
	}

	_ = result.RootCAPool
	_ = result.RuntimeEval
}

func TestOptionsParity_ProductionOptionsBootstrapSucceeds(t *testing.T) {
	cfg := wiringtest.DevConfigNoSignatures(18081)

	deps.ResetDeps()

	result, err := wiring.Build(cfg, wiringtest.DiscardLogger(), wiring.BuildOpts{})
	if err != nil {
		t.Fatalf("Build with production (zero) options failed: %v", err)
	}

	if result.RuntimeEval.DerivedTier == "" {
		t.Error("RuntimeEval.DerivedTier is empty; Build must populate it")
	}
}
