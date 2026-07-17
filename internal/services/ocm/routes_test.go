package ocm

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRegisteredRouteSpecs(t *testing.T) {
	opts := service.DefaultRouteOpts()
	specs := registeredRouteSpecs(opts)
	if len(specs) != 5 {
		t.Fatalf("expected 5 route specs, got %d", len(specs))
	}
	var requestShare *service.RouteSpec
	for i := range specs {
		spec := specs[i]
		if spec.SurfaceClass != service.SurfaceProtocol {
			t.Errorf("spec %q surface = %q, want protocol", spec.ID, spec.SurfaceClass)
		}
		if spec.SessionPolicy != service.SessionPublic {
			t.Errorf("spec %q session = %q, want public", spec.ID, spec.SessionPolicy)
		}
		if spec.ID == "ocm-request-share" {
			requestShare = &specs[i]
		}
	}
	if requestShare == nil {
		t.Fatal("expected ocm-request-share route spec")
	}
	if requestShare.Method != "POST" {
		t.Errorf("request-share method = %q, want POST", requestShare.Method)
	}
	if requestShare.Pattern != RouteRequestShare {
		t.Errorf("request-share pattern = %q, want %q", requestShare.Pattern, RouteRequestShare)
	}
	if requestShare.TrustClass != service.TrustPeerRequired {
		t.Errorf("request-share trust = %q, want %q", requestShare.TrustClass, service.TrustPeerRequired)
	}
	if requestShare.HandlerAuth != service.HandlerAuthOptionalHTTPSig {
		t.Errorf("request-share handler auth = %q, want %q", requestShare.HandlerAuth, service.HandlerAuthOptionalHTTPSig)
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
