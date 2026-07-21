package wellknown

import (
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRegisteredRouteSpecs(t *testing.T) {
	opts := service.DefaultRouteOpts()
	specs := registeredRouteSpecs(opts)
	if len(specs) != 3 {
		t.Fatalf("expected 3 route specs, got %d", len(specs))
	}
	for _, spec := range specs {
		if spec.Service != "wellknown" {
			t.Errorf("spec %q has service %q, want wellknown", spec.ID, spec.Service)
		}
		if spec.SurfaceClass != service.SurfaceDiscovery {
			t.Errorf("spec %q surface = %q, want discovery", spec.ID, spec.SurfaceClass)
		}
		if len(spec.DiscoveryFields) == 0 {
			t.Errorf("spec %q missing discovery fields", spec.ID)
		}
		if spec.Pattern == "/ocm-provider" || spec.Pattern == "/ocm-provider/" {
			t.Errorf("spec %q must not register legacy path %q", spec.ID, spec.Pattern)
		}
	}
}

func TestRouteConstants_MatchChiRegistration(t *testing.T) {
	paths := []string{
		RouteWellKnownOCM,
		RouteWellKnownOCMSlash,
		RouteWellKnownJWKS,
	}
	specs := registeredRouteSpecs(service.DefaultRouteOpts())
	if len(paths) != len(specs) {
		t.Fatalf("constant count = %d, spec count = %d", len(paths), len(specs))
	}
	for i, path := range paths {
		if specs[i].Pattern != path {
			t.Errorf("spec pattern = %q, want constant %q", specs[i].Pattern, path)
		}
	}

	patterns := make([]string, len(specs))
	for i, spec := range specs {
		patterns[i] = spec.Pattern
	}
	for _, legacy := range []string{"/ocm-provider", "/ocm-provider/"} {
		if slices.Contains(patterns, legacy) {
			t.Errorf("registered route specs must not include legacy path %q", legacy)
		}
	}
}
