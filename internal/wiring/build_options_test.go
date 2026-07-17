package wiring_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestOptions_HarnessBootstrapSucceeds(t *testing.T) {
	cfg := config.DevConfig()

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build with harness options failed: %v", err)
	}

	_ = result.RootCAPool
	_ = result.RuntimeEval
}

func TestOptions_ProductionBootstrapSucceeds(t *testing.T) {
	cfg := config.DevConfig()

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), wiring.BuildOpts{})
	if err != nil {
		t.Fatalf("Build with production (zero) options failed: %v", err)
	}

	if result.RuntimeEval.DerivedTier == "" {
		t.Error("RuntimeEval.DerivedTier is empty; Build must populate it")
	}
}
