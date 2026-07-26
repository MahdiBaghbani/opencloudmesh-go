package wiring_test

import (
	"reflect"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	tsrouting "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/routing"
	tswiring "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestFixtures_HarnessWireOptionsMatchIntegrationHarness(t *testing.T) {
	got := harness.IntegrationBuildOpts()

	want := toBuildOpts(tswiring.HarnessWireOptions)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("IntegrationBuildOpts() = %+v, want %+v", got, want)
	}
}

func TestFixtures_IETFWireOptionsMatchIntegrationHarness(t *testing.T) {
	got := harness.IETFIntegrationBuildOpts()

	want := toBuildOpts(tswiring.IETFWireOptions)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("IETFIntegrationBuildOpts() = %+v, want %+v", got, want)
	}

	if got.SkipCrypto {
		t.Fatal("IETF wire options must enable crypto")
	}
}

func TestFixtures_HarnessWireOptionsFixture(t *testing.T) {
	fixture := tswiring.HarnessWireOptions
	if !fixture.FastAuth || fixture.SkipCrypto || !fixture.SkipPeerTrust ||
		!fixture.SkipDiscoveryCache {
		t.Fatalf("harness fixture must enable crypto and keep transport skips, got %+v", fixture)
	}

	if fixture.OutboundOverride == nil {
		t.Fatal("harness fixture must include OutboundOverride")
	}
}

func TestFixtures_ProductionZeroValueBuildSucceeds(t *testing.T) {
	cfg := config.DevConfig()

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), wiring.BuildOpts{})
	if err != nil {
		t.Fatalf("Build with zero opts failed: %v", err)
	}

	if result.Deps == nil {
		t.Fatal("Build must return explicit Deps in BuildResult")
	}
}

func TestFixtures_RoutePolicyPublicPaths(t *testing.T) {
	cfg := config.DevConfig()
	opts := tswiring.RouteOptsForConfig(cfg)
	want := tsrouting.PublicSessionPaths(opts)

	if !reflect.DeepEqual(want, tswiring.ExpectedPublicSessionPaths) {
		t.Fatalf("public session paths = %v, want fixture %v", want, tswiring.ExpectedPublicSessionPaths)
	}
}
