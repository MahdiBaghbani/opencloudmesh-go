package ocm

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRegisteredRouteSpecs(t *testing.T) {
	opts := service.DefaultRouteOpts()
	specs := registeredRouteSpecs(opts)
	if len(specs) != 4 {
		t.Fatalf("expected 4 route specs, got %d", len(specs))
	}
	for _, spec := range specs {
		if spec.SurfaceClass != service.SurfaceProtocol {
			t.Errorf("spec %q surface = %q, want protocol", spec.ID, spec.SurfaceClass)
		}
		if spec.SessionPolicy != service.SessionPublic {
			t.Errorf("spec %q session = %q, want public", spec.ID, spec.SessionPolicy)
		}
	}
}

func TestRegisteredRouteSpecs_CustomTokenPath(t *testing.T) {
	opts := service.DefaultRouteOpts()
	opts.TokenExchangePath = "exchange"
	specs := registeredRouteSpecs(opts)
	found := false
	for _, spec := range specs {
		if spec.Pattern == "/exchange" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected token route spec for custom path /exchange")
	}
}
