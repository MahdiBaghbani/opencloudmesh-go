package service_test

import (
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
)

// TestCoreServiceNamesMatchesCoreServices verifies the wiring table matches
// service.CoreServices. Lives in service_test to avoid an import cycle (wiring
// imports service).
func TestCoreServiceNamesMatchesCoreServices(t *testing.T) {
	if !slices.Equal(wiring.CoreServiceNames(), service.CoreServices) {
		t.Errorf(
			"wiring.CoreServiceNames() = %v, want service.CoreServices %v",
			wiring.CoreServiceNames(),
			service.CoreServices,
		)
	}
}

// TestCoreServiceBuildersCoverDescriptors verifies every descriptor build key
// has a wiring builder and that no orphan builders exist.
func TestCoreServiceBuildersCoverDescriptors(t *testing.T) {
	descs := service.Descriptors()

	registered := make(map[service.BuildKey]struct{}, len(wiring.RegisteredBuildKeys()))
	for _, k := range wiring.RegisteredBuildKeys() {
		registered[k] = struct{}{}
	}

	seen := make(map[service.BuildKey]string, len(descs))
	for _, d := range descs {
		if d.Build == "" {
			t.Errorf("descriptor %q has no build key", d.Name)
			continue
		}

		if prev, ok := seen[d.Build]; ok {
			t.Errorf("duplicate build key %q for services %q and %q", d.Build, prev, d.Name)
		}

		seen[d.Build] = d.Name
		if _, ok := registered[d.Build]; !ok {
			t.Errorf("descriptor %q build key %q has no wiring builder", d.Name, d.Build)
		}
	}

	for k := range registered {
		if _, ok := seen[k]; !ok {
			t.Errorf("wiring builder %q is not referenced by any descriptor", k)
		}
	}
}
