package wiring_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	tscfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/cfg"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	wiringtest "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestFixtures_HarnessWireOptionsMatchIntegrationHarness(t *testing.T) {
	got := harness.IntegrationBuildOpts()
	want := toBuildOpts(wiringtest.HarnessWireOptions)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("IntegrationBuildOpts() = %+v, want %+v", got, want)
	}
}

func TestFixtures_HarnessWireOptionsFixture(t *testing.T) {
	fixture := wiringtest.HarnessWireOptions
	if !fixture.FastAuth || !fixture.SkipCrypto || !fixture.SkipPeerTrust ||
		!fixture.SkipSignatureMiddleware || !fixture.SkipDiscoveryCache {
		t.Fatalf("harness fixture must keep harness skip flags enabled, got %+v", fixture)
	}
	if fixture.OutboundOverride == nil {
		t.Fatal("harness fixture must include OutboundOverride")
	}
	got := toBuildOpts(fixture)
	want := wiring.BuildOpts{
		FastAuth:                fixture.FastAuth,
		SkipCrypto:              fixture.SkipCrypto,
		SkipPeerTrust:           fixture.SkipPeerTrust,
		SkipSignatureMiddleware: fixture.SkipSignatureMiddleware,
		OutboundOverride:        fixture.OutboundOverride,
		SkipDiscoveryCache:      fixture.SkipDiscoveryCache,
	}
	if got != want {
		t.Fatalf("BuildOpts conversion must preserve harness fixture, got %+v want %+v", got, want)
	}
}

func TestFixtures_ProductionZeroValueStruct(t *testing.T) {
	var got wiring.BuildOpts
	var want wiring.BuildOpts
	if got != want {
		t.Fatalf("zero BuildOpts = %+v, want zero value", got)
	}
	if got.FastAuth || got.SkipCrypto || got.SkipPeerTrust ||
		got.SkipSignatureMiddleware || got.SkipDiscoveryCache || got.OutboundOverride != nil {
		t.Fatalf("production BuildOpts must remain zero-valued, got %+v", got)
	}
	if !reflect.ValueOf(wiringtest.ProductionWireOptions).IsZero() {
		t.Fatal("ProductionWireOptions must remain zero-valued")
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

func TestFixtures_CoreServicesOrder(t *testing.T) {
	if !slices.Equal(service.CoreServices, wiringtest.ExpectedCoreServicesOrder) {
		t.Fatalf("CoreServices = %v, want %v",
			service.CoreServices, wiringtest.ExpectedCoreServicesOrder)
	}
}

func TestFixtures_RootService(t *testing.T) {
	if service.RootService != wiringtest.ExpectedRootService {
		t.Fatalf("RootService = %q, want %q", service.RootService, wiringtest.ExpectedRootService)
	}
}

func TestFixtures_AppServicesOrder(t *testing.T) {
	got := service.AppServices()
	if !slices.Equal(got, wiringtest.ExpectedAppServicesOrder) {
		t.Fatalf("AppServices() = %v, want %v", got, wiringtest.ExpectedAppServicesOrder)
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

	for _, want := range wiringtest.ExpectedUnprotectedSets {
		t.Run(want.Service, func(t *testing.T) {
			svc, ok := services[want.Service]
			if !ok {
				t.Fatalf("service %q missing from static table", want.Service)
			}
			t.Cleanup(func() { _ = svc.Close() })

			got := append([]string(nil), svc.Unprotected()...)
			if !reflect.DeepEqual(got, want.Paths) {
				t.Fatalf("Unprotected() = %v, want %v", got, want.Paths)
			}
		})
	}
}
