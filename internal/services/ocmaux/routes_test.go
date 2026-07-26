package ocmaux

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRegisteredRouteSpecs(t *testing.T) {
	specs := registeredRouteSpecs(service.DefaultRouteOpts())
	if len(specs) != 2 {
		t.Fatalf("expected 2 route specs, got %d", len(specs))
	}

	for _, spec := range specs {
		if spec.SurfaceClass != service.SurfaceHelper {
			t.Errorf("spec %q surface = %q, want helper", spec.ID, spec.SurfaceClass)
		}

		if spec.SessionPolicy != service.SessionPublic {
			t.Errorf("spec %q session = %q, want public", spec.ID, spec.SessionPolicy)
		}
	}
}
