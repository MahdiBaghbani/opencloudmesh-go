package ocm

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRegisteredRouteSpecs(t *testing.T) {
	opts := service.DefaultRouteOpts()
	specs := registeredRouteSpecs(opts)
	if len(specs) != 3 {
		t.Fatalf("expected 3 route specs, got %d", len(specs))
	}
	for i := range specs {
		spec := specs[i]
		if spec.SurfaceClass != service.SurfaceProtocol {
			t.Errorf("spec %q surface = %q, want protocol", spec.ID, spec.SurfaceClass)
		}
		if spec.SessionPolicy != service.SessionPublic {
			t.Errorf("spec %q session = %q, want public", spec.ID, spec.SessionPolicy)
		}
		if spec.TrustClass != service.TrustPeerRequired {
			t.Errorf("spec %q trust = %q, want %q", spec.ID, spec.TrustClass, service.TrustPeerRequired)
		}
		if spec.HandlerAuth != service.HandlerAuthRequiredHTTPSig {
			t.Errorf("spec %q handler auth = %q, want %q", spec.ID, spec.HandlerAuth, service.HandlerAuthRequiredHTTPSig)
		}
	}
}

func TestRegisteredRouteSpecs_ProtocolPostInvariants(t *testing.T) {
	opts := service.DefaultRouteOpts()
	var postRows []service.RouteSpec
	for _, spec := range registeredRouteSpecs(opts) {
		if spec.Service != "ocm" || spec.Method != "POST" ||
			spec.SurfaceClass != service.SurfaceProtocol {
			continue
		}
		postRows = append(postRows, spec)
	}
	if len(postRows) != 3 {
		t.Fatalf("expected 3 OCM POST protocol route specs, got %d", len(postRows))
	}
	for _, spec := range postRows {
		if spec.HandlerAuth != service.HandlerAuthRequiredHTTPSig {
			t.Errorf("spec %q handler auth = %q, want %q",
				spec.ID, spec.HandlerAuth, service.HandlerAuthRequiredHTTPSig)
		}
		if spec.BodyLimitBytes != service.OCMProtocolBodyLimitBytes {
			t.Errorf("spec %q body limit = %d, want %d",
				spec.ID, spec.BodyLimitBytes, service.OCMProtocolBodyLimitBytes)
		}
		if spec.BodyLimitBytes <= 0 {
			t.Errorf("spec %q body limit = %d, want positive", spec.ID, spec.BodyLimitBytes)
		}
		if spec.PeerResolution == "" {
			t.Errorf("spec %q peer resolution is empty", spec.ID)
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
