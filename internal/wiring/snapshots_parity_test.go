package wiring_test

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestSnapshots_HarnessWireOptionsSourceAnchorParityWithHarnessTest(t *testing.T) {
	root := wiringtest.ModuleRoot(t)
	harnessTestPath := filepath.Join(root, "tests/integration/harness/behavior_snapshot_test.go")
	body, err := os.ReadFile(harnessTestPath)
	if err != nil {
		t.Fatalf("read behavior_snapshot_test.go: %v", err)
	}
	text := string(body)
	for _, needle := range wiringtest.SnapshotHarnessWireOptionsSourceNeedles {
		if !strings.Contains(text, needle) {
			t.Fatalf("harness behavior_snapshot_test.go missing shared needle %q", needle)
		}
	}
}

func TestSnapshots_HarnessWireOptionsSourceAnchor(t *testing.T) {
	root := wiringtest.ModuleRoot(t)
	harnessPath := filepath.Join(root, "tests/integration/harness/harness.go")
	body, err := os.ReadFile(harnessPath)
	if err != nil {
		t.Fatalf("read harness.go: %v", err)
	}
	text := string(body)

	for _, needle := range wiringtest.SnapshotHarnessWireOptionsSourceNeedles {
		if !strings.Contains(text, needle) {
			t.Fatalf("harness.go bootstrap WireOptions source anchor missing %q", needle)
		}
	}
}

func TestSnapshots_HarnessWireOptionsFixture(t *testing.T) {
	fixture := wiringtest.SnapshotHarnessWireOptions
	if !fixture.FastAuth || !fixture.SkipCrypto || !fixture.SkipPeerTrust ||
		!fixture.SkipSignatureMiddleware || !fixture.SkipDiscoveryCache {
		t.Fatalf("harness T0 fixture must keep harness skip flags enabled, got %+v", fixture)
	}
	if fixture.OutboundOverride == nil {
		t.Fatal("harness T0 fixture must include OutboundOverride")
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

func TestSnapshots_ProductionZeroValueMainAnchor(t *testing.T) {
	root := wiringtest.ModuleRoot(t)
	mainPath := filepath.Join(root, "cmd/opencloudmesh-go/main.go")
	body, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	text := string(body)

	for _, needle := range []string{
		`result, err := wiring.Build(cfg, logger, wiring.BuildOpts{})`,
		`wiring.Build(cfg, logger, wiring.BuildOpts{})`,
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("production zero-value wiring path missing %q", needle)
		}
	}
}

func TestSnapshots_ProductionZeroValueStruct(t *testing.T) {
	var got wiring.BuildOpts
	var want wiring.BuildOpts
	if got != want {
		t.Fatalf("zero BuildOpts = %+v, want zero value", got)
	}
	if got.FastAuth || got.SkipCrypto || got.SkipPeerTrust ||
		got.SkipSignatureMiddleware || got.SkipDiscoveryCache || got.OutboundOverride != nil {
		t.Fatalf("production BuildOpts must remain zero-valued, got %+v", got)
	}
	if !reflect.ValueOf(wiringtest.SnapshotProductionWireOptions).IsZero() {
		t.Fatal("SnapshotProductionWireOptions must remain zero-valued")
	}
}

func TestSnapshots_CoreServicesOrder(t *testing.T) {
	if !slices.Equal(service.CoreServices, wiringtest.SnapshotCoreServicesOrder) {
		t.Fatalf("CoreServices = %v, want snapshot %v",
			service.CoreServices, wiringtest.SnapshotCoreServicesOrder)
	}
}

func TestSnapshots_RootService(t *testing.T) {
	if service.RootService != wiringtest.SnapshotRootService {
		t.Fatalf("RootService = %q, want %q", service.RootService, wiringtest.SnapshotRootService)
	}
}

func TestSnapshots_AppServicesOrder(t *testing.T) {
	got := service.AppServices()
	if !slices.Equal(got, wiringtest.SnapshotAppServicesOrder) {
		t.Fatalf("AppServices() = %v, want snapshot %v", got, wiringtest.SnapshotAppServicesOrder)
	}
}

func TestSnapshots_UnprotectedSets(t *testing.T) {
	cfg := wiringtest.DevConfigNoSignatures(18100)

	result, err := wiring.Build(cfg, wiringtest.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	services, err := wiring.BuildCoreServices(cfg, wiringtest.DiscardLogger(), result.Deps)
	if err != nil {
		t.Fatalf("BuildCoreServices failed: %v", err)
	}

	for _, want := range wiringtest.SnapshotUnprotectedSets {
		t.Run(want.Service, func(t *testing.T) {
			svc, ok := services[want.Service]
			if !ok {
				t.Fatalf("service %q missing from static table", want.Service)
			}
			t.Cleanup(func() { _ = svc.Close() })

			got := append([]string(nil), svc.Unprotected()...)
			if !reflect.DeepEqual(got, want.Paths) {
				t.Fatalf("Unprotected() = %v, want snapshot %v", got, want.Paths)
			}
		})
	}
}

func TestSnapshots_CoreServicesRegistrySourceAnchor(t *testing.T) {
	root := wiringtest.ModuleRoot(t)
	registryPath := filepath.Join(root, "internal/frameworks/service/registry.go")
	body, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatalf("read registry.go: %v", err)
	}
	text := string(body)

	for _, needle := range []string{
		`var CoreServices = []string{"wellknown", "ocm", "ocmaux", "api", "ui", "webdav"}`,
		`const RootService = "wellknown"`,
		`func AppServices() []string {`,
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("registry.go anchor missing %q", needle)
		}
	}
}
