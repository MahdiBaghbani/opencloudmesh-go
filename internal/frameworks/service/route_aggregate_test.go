package service_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/api"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocmaux"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/wellknown"
)

func TestRoutes_IsCanonicalAggregate(t *testing.T) {
	opts := service.DefaultRouteOpts()
	inventory := service.DerivedRouteInventory(opts)
	rows := service.Routes(opts)

	productCount := 0
	for _, row := range rows {
		if !row.Synthetic {
			productCount++
		}
	}
	if productCount != len(inventory) {
		t.Fatalf("Routes product count = %d, inventory = %d", productCount, len(inventory))
	}
}

func TestRoutes_ProductRowsHavePolicyMetadata(t *testing.T) {
	opts := service.DefaultRouteOpts()
	for _, row := range service.Routes(opts) {
		if row.Synthetic {
			continue
		}
		if row.SurfaceClass == "" {
			t.Errorf("product route %q missing SurfaceClass", row.ID)
		}
		if row.HandlerAuth == "" {
			t.Errorf("product route %q missing HandlerAuth", row.ID)
		}
		if row.TrustClass == "" {
			t.Errorf("product route %q missing TrustClass", row.ID)
		}
	}
}

func TestRoutes_SyntheticRowsHaveSurfaceClass(t *testing.T) {
	opts := service.DefaultRouteOpts()
	for _, row := range service.Routes(opts) {
		if !row.Synthetic {
			continue
		}
		if row.SurfaceClass == "" {
			t.Errorf("synthetic row %q missing SurfaceClass", row.ID)
		}
	}
}

func TestRoutes_ProtocolRowsUseHTTPSigHandlerAuth(t *testing.T) {
	opts := service.DefaultRouteOpts()
	for _, row := range service.Routes(opts) {
		if row.Synthetic || row.SurfaceClass != service.SurfaceProtocol {
			continue
		}
		if row.HandlerAuth != service.HandlerAuthRequiredHTTPSig {
			t.Errorf("protocol route %q HandlerAuth = %q, want required HTTP signature", row.ID, row.HandlerAuth)
		}
	}
}

func TestRoutes_APIOutboundKindsDeclaredOnAPIRows(t *testing.T) {
	opts := service.DefaultRouteOpts()
	found := map[service.OutboundProtocolKind]bool{
		service.OutboundShares:  false,
		service.OutboundInvites: false,
		service.OutboundAccess:  false,
	}
	for _, row := range service.Routes(opts) {
		if row.Synthetic || row.SurfaceClass != service.SurfaceAPI {
			continue
		}
		if row.OutboundProtocolKind == service.OutboundNone {
			continue
		}
		found[row.OutboundProtocolKind] = true
	}
	for kind, ok := range found {
		if !ok {
			t.Errorf("Routes(opts) missing api row with outbound kind %q", kind)
		}
	}
}
