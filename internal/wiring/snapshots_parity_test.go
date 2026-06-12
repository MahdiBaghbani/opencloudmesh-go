package wiring_test

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/loader"
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
	got := wiring.BuildOpts(fixture)
	if !reflect.DeepEqual(got, fixture) {
		t.Fatalf("BuildOpts alias must preserve harness fixture, got %+v want %+v", got, fixture)
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
	if !reflect.DeepEqual(got, wiringtest.SnapshotProductionWireOptions) {
		t.Fatalf("zero BuildOpts = %+v, want snapshot %+v", got, wiringtest.SnapshotProductionWireOptions)
	}
	if got.FastAuth || got.SkipCrypto || got.SkipPeerTrust ||
		got.SkipSignatureMiddleware || got.SkipDiscoveryCache || got.OutboundOverride != nil {
		t.Fatalf("production BuildOpts must remain zero-valued, got %+v", got)
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

func TestSnapshots_RegisteredServicesCoverCoreServices(t *testing.T) {
	registered := service.RegisteredServices()
	for _, name := range service.CoreServices {
		if service.Get(name) == nil {
			t.Errorf("core service %q is not registered", name)
		}
		if !slices.Contains(registered, name) {
			t.Errorf("RegisteredServices() missing core service %q", name)
		}
	}
}

func TestSnapshots_UnprotectedSets(t *testing.T) {
	cfg := wiringtest.DevConfigNoSignatures(18100)
	deps.ResetDeps()
	t.Cleanup(deps.ResetDeps)

	_, err := wiring.Build(cfg, wiringtest.DiscardLogger(), wiringtest.HarnessWireOptions())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	log := wiringtest.DiscardLogger()
	for _, want := range wiringtest.SnapshotUnprotectedSets {
		t.Run(want.Service, func(t *testing.T) {
			newFn := service.Get(want.Service)
			if newFn == nil {
				t.Fatalf("service %q not registered", want.Service)
			}
			svcCfg := cfg.BuildServiceConfig(want.Service)
			if svcCfg == nil {
				svcCfg = map[string]any{}
			}
			svc, err := newFn(svcCfg, log)
			if err != nil {
				t.Fatalf("construct %q: %v", want.Service, err)
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
