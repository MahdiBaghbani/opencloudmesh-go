package wiring_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/app"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestDiscoveryCacheParity_SkipDiscoveryCacheWiresClient(t *testing.T) {
	t.Run("SkipDiscoveryCache=true wires NoopCache to discovery client", func(t *testing.T) {
		deps.ResetDeps()
		_, err := app.BootstrapDeps(
			wiringtest.DevConfigNoSignatures(18088),
			wiringtest.DiscardLogger(),
			wiringtest.HarnessWireOptions(),
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := deps.GetDeps()
		if !d.DiscoveryClient.IsNoopCache() {
			t.Error("expected NoopCache when SkipDiscoveryCache=true, got a different cache")
		}
		if d.Cache == nil {
			t.Fatal("deps.Cache must be non-nil even when SkipDiscoveryCache=true")
		}
	})

	t.Run("SkipDiscoveryCache=false wires shared cache to discovery client", func(t *testing.T) {
		deps.ResetDeps()
		opts := wiringtest.HarnessWireOptions()
		opts.SkipDiscoveryCache = false
		_, err := app.BootstrapDeps(
			wiringtest.DevConfigNoSignatures(18089),
			wiringtest.DiscardLogger(),
			opts,
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := deps.GetDeps()
		if d.DiscoveryClient.IsNoopCache() {
			t.Error("discovery client must not use NoopCache when SkipDiscoveryCache=false")
		}
		if d.Cache == nil {
			t.Fatal("deps.Cache must be non-nil when SkipDiscoveryCache=false")
		}
	})
}
