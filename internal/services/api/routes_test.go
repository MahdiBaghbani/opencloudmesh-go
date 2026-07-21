package api

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRegisteredRouteSpecs(t *testing.T) {
	specs := registeredRouteSpecs(service.DefaultRouteOpts())
	if len(specs) < 10 {
		t.Fatalf("expected many api route specs, got %d", len(specs))
	}
	for _, spec := range specs {
		if spec.SurfaceClass != service.SurfaceAPI {
			t.Errorf("spec %q surface = %q, want api", spec.ID, spec.SurfaceClass)
		}
	}
}

func TestRegisteredRouteSpecs_OutboundProtocolKinds(t *testing.T) {
	specs := registeredRouteSpecs(service.DefaultRouteOpts())
	found := map[service.OutboundProtocolKind]bool{
		service.OutboundShares:  false,
		service.OutboundInvites: false,
		service.OutboundAccess:  false,
	}
	for _, spec := range specs {
		if spec.OutboundProtocolKind != "" {
			found[spec.OutboundProtocolKind] = true
		}
	}
	for kind, ok := range found {
		if !ok {
			t.Errorf("expected api route with outbound kind %q", kind)
		}
	}
}
