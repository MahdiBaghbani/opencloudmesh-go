package ui

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRegisteredRouteSpecs_BaseRoutes(t *testing.T) {
	specs := registeredRouteSpecs(service.DefaultRouteOpts())
	baseCount := 0
	for _, spec := range specs {
		if spec.FeatureCondition == service.FeatureNone {
			baseCount++
		}
	}
	if baseCount != 3 {
		t.Fatalf("expected 3 base ui route specs, got %d", baseCount)
	}
}

func TestRegisteredRouteSpecs_WayfAndAcceptInviteSeparate(t *testing.T) {
	enabled := service.RouteOpts{
		WayfEnabled:         true,
		InviteAcceptEnabled: true,
		TokenExchangePath:   "token",
	}
	var specs []service.RouteSpec
	for _, spec := range service.RegisteredRouteSpecs(enabled) {
		if spec.Service == "ui" {
			specs = append(specs, spec)
		}
	}
	if len(specs) != 5 {
		t.Fatalf("expected 5 ui route specs with WAYF, got %d", len(specs))
	}

	var wayfSpec, acceptSpec *service.RouteSpec
	for i := range specs {
		switch specs[i].Pattern {
		case RouteWAYF:
			wayfSpec = &specs[i]
		case RouteAcceptInvite:
			acceptSpec = &specs[i]
		}
	}
	if wayfSpec == nil || acceptSpec == nil {
		t.Fatal("expected separate wayf and accept-invite route specs")
	}
	if wayfSpec.FeatureCondition != service.FeatureWAYFEnabled {
		t.Errorf("wayf feature = %q, want WAYF enabled", wayfSpec.FeatureCondition)
	}
	if acceptSpec.FeatureCondition != service.FeatureInviteAcceptEnabled {
		t.Errorf("accept-invite feature = %q, want invite accept enabled", acceptSpec.FeatureCondition)
	}
	if wayfSpec.SessionPolicy != service.SessionPublicWhenWAYF {
		t.Errorf("wayf session = %q, want public when WAYF enabled", wayfSpec.SessionPolicy)
	}
	if acceptSpec.SessionPolicy != service.SessionProtected {
		t.Errorf("accept-invite session = %q, want protected", acceptSpec.SessionPolicy)
	}
}
