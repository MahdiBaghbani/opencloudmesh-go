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
}

func TestOptions_ProductionBootstrapSucceeds(t *testing.T) {
	cfg := config.DevConfig()

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), wiring.BuildOpts{})
	if err != nil {
		t.Fatalf("Build with production (zero) options failed: %v", err)
	}

	if result.Deps.CodeFlow == nil {
		t.Fatal("CodeFlow is nil; Build must populate it")
	}
	if facts := result.Deps.CodeFlow.Evaluate(); !facts.TokenExchangeCapable {
		t.Error("expected Build-populated CodeFlow.Evaluate() to report TokenExchangeCapable")
	}
}
