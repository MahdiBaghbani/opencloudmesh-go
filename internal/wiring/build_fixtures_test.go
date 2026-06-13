package wiring_test

import (
	"reflect"
	"testing"

	tscfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/cfg"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
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

func TestFixtures_HarnessWireOptionsFixture(t *testing.T) {
	fixture := tswiring.HarnessWireOptions
	if !fixture.FastAuth || !fixture.SkipCrypto || !fixture.SkipPeerTrust ||
		!fixture.SkipSignatureMiddleware || !fixture.SkipDiscoveryCache {
		t.Fatalf("harness fixture must keep harness skip flags enabled, got %+v", fixture)
	}
	if fixture.OutboundOverride == nil {
		t.Fatal("harness fixture must include OutboundOverride")
	}
}

func TestFixtures_ProductionZeroValueBuildSucceeds(t *testing.T) {
	cfg := tscfg.DevConfigNoSignatures(18112)

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), wiring.BuildOpts{})
	if err != nil {
		t.Fatalf("Build with zero opts failed: %v", err)
	}
	if result.Deps == nil {
		t.Fatal("Build must return explicit Deps in BuildResult")
	}
}

func TestFixtures_UnprotectedSets(t *testing.T) {
	cfg := tscfg.DevConfigNoSignatures(18100)

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	services, err := wiring.BuildCoreServices(cfg, tslog.DiscardLogger(), result.Deps)
	if err != nil {
		t.Fatalf("BuildCoreServices failed: %v", err)
	}

	for _, want := range tswiring.ExpectedUnprotectedSets {
		t.Run(want.Service, func(t *testing.T) {
			svc, ok := services[want.Service]
			if !ok {
				t.Fatalf("service %q missing from built services", want.Service)
			}
			t.Cleanup(func() { _ = svc.Close() })

			got := append([]string(nil), svc.Unprotected()...)
			if !reflect.DeepEqual(got, want.Paths) {
				t.Fatalf("Unprotected() = %v, want %v", got, want.Paths)
			}
		})
	}
}
