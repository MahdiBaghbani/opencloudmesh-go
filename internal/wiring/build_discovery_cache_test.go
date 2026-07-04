package wiring_test

import (
	tscfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/cfg"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestDiscoveryCacheSkip_WiresClient(t *testing.T) {
	t.Run("SkipDiscoveryCache=true wires NoopCache to discovery client", func(t *testing.T) {
		result, err := wiring.Build(
			tscfg.DevConfigNoSignatures(),
			tslog.DiscardLogger(),
			harnessBuildOpts(),
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := result.Deps
		if !d.DiscoveryClient.IsNoopCache() {
			t.Error("expected NoopCache when SkipDiscoveryCache=true, got a different cache")
		}
		if d.Cache == nil {
			t.Fatal("Deps.Cache must be non-nil even when SkipDiscoveryCache=true")
		}
	})

	t.Run("SkipDiscoveryCache=false wires shared cache to discovery client", func(t *testing.T) {
		opts := harnessBuildOpts()
		opts.SkipDiscoveryCache = false
		result, err := wiring.Build(
			tscfg.DevConfigNoSignatures(),
			tslog.DiscardLogger(),
			opts,
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := result.Deps
		if d.DiscoveryClient.IsNoopCache() {
			t.Error("discovery client must not use NoopCache when SkipDiscoveryCache=false")
		}
		if d.Cache == nil {
			t.Fatal("Deps.Cache must be non-nil when SkipDiscoveryCache=false")
		}
	})
}
