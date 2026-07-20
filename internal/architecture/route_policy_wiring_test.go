package architecture

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	tsrouting "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/routing"
)

func TestRoutePolicyProjections_DerivedFromRoutes(t *testing.T) {
	opts := tsrouting.DevOpts()
	routes := service.Routes(opts)
	authRows := service.DerivedAuthRows(opts)
	groups := service.DerivedMountSpecs(opts)
	inventory := service.DerivedRouteInventory(opts)

	if len(authRows) != len(routes) {
		t.Fatalf("DerivedAuthRows count = %d, Routes count = %d", len(authRows), len(routes))
	}
	if len(groups) == 0 {
		t.Fatal("DerivedMountSpecs returned no mount specs")
	}
	if len(inventory) == 0 {
		t.Fatal("DerivedRouteInventory returned no product routes")
	}

	byPrefix := make(map[string]service.DerivedRouteGroup, len(groups))
	for _, g := range groups {
		byPrefix[g.PathPrefix] = g
	}
	for _, row := range routes {
		if row.Synthetic && !row.AtHostRoot {
			g, ok := byPrefix[row.FullPath]
			if !ok {
				t.Errorf("missing subtree group for synthetic row %q", row.FullPath)
				continue
			}
			if g.Name != row.Service || g.AtHostRoot {
				t.Errorf("subtree group %+v does not match synthetic row %+v", g, row)
			}
			wantAuth := service.SessionAuthRequiredForPath(row.FullPath+"/probe", opts)
			if g.RequiresAuth != wantAuth {
				t.Errorf("subtree group %q RequiresAuth = %v, want %v", row.FullPath, g.RequiresAuth, wantAuth)
			}
		}
	}

	for _, row := range inventory {
		if row.SurfaceClass == "" || row.HandlerAuth == "" || row.TrustClass == "" {
			t.Errorf("inventory row %q missing metadata: %+v", row.ID, row)
		}
	}
}

func TestRoutePolicyWiring_NoDuplicateAuthTruth(t *testing.T) {
	opts := tsrouting.DevOpts()
	for _, path := range tsrouting.PublicSessionPaths(opts) {
		if service.SessionAuthRequiredForPath(path, opts) {
			t.Errorf("expected public session path %q", path)
		}
	}
	for _, path := range tsrouting.ProtectedSessionPaths(opts) {
		if !service.SessionAuthRequiredForPath(path, opts) {
			t.Errorf("expected protected session path %q", path)
		}
	}
}

func TestRoutePolicyWiring_ProductRoutesHavePolicyMetadata(t *testing.T) {
	opts := tsrouting.DevOpts()
	for _, row := range tsrouting.ProductRoutes(opts) {
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

func TestRoutePolicyWiring_SyntheticRowsHaveSurfaceClass(t *testing.T) {
	opts := tsrouting.DevOpts()
	for _, row := range tsrouting.SyntheticRoutes(opts) {
		if row.SurfaceClass == "" {
			t.Errorf("synthetic row %q missing SurfaceClass", row.ID)
		}
	}
}

func TestRoutePolicyWiring_HTTPsigHandlerAuthOnlyOnOCMProtocol(t *testing.T) {
	opts := tsrouting.DevOpts()
	for _, row := range tsrouting.ProductRoutes(opts) {
		switch row.HandlerAuth {
		case service.HandlerAuthRequiredHTTPSig:
			if row.SurfaceClass != service.SurfaceProtocol {
				t.Errorf("route %q HandlerAuth %q on surface %q, want protocol", row.ID, row.HandlerAuth, row.SurfaceClass)
			}
			if row.Service != "ocm" {
				t.Errorf("route %q HandlerAuth %q on service %q, want ocm", row.ID, row.HandlerAuth, row.Service)
			}
			if !tsrouting.IsOCMProtocolPath(row.FullPath, opts) {
				t.Errorf("route %q HandlerAuth %q full path %q, want /ocm/* prefix", row.ID, row.HandlerAuth, row.FullPath)
			}
		default:
			if row.SurfaceClass == service.SurfaceProtocol {
				t.Errorf("protocol route %q HandlerAuth = %q, want required HTTP signature", row.ID, row.HandlerAuth)
			}
		}
	}
}

func TestRoutePolicyWiring_ProtocolRoutesHavePeerTrustClass(t *testing.T) {
	opts := tsrouting.DevOpts()
	for _, row := range tsrouting.ProtocolRoutes(opts) {
		switch row.TrustClass {
		case service.TrustPeerRequired:
		default:
			t.Errorf("protocol route %q TrustClass = %q, want peer-trust-required", row.ID, row.TrustClass)
		}
	}
}

func TestRoutePolicyWiring_AuxAndUIExcludedFromProtocolTrust(t *testing.T) {
	opts := tsrouting.DevOpts()
	for _, surface := range []service.SurfaceClass{service.SurfaceHelper, service.SurfaceUI} {
		for _, row := range tsrouting.RoutesBySurface(opts, surface) {
			if row.TrustClass != service.TrustPeerNone {
				t.Errorf("%s route %q TrustClass = %q, want peer-trust-none", surface, row.ID, row.TrustClass)
			}
			if row.HandlerAuth == service.HandlerAuthRequiredHTTPSig {
				t.Errorf("%s route %q uses HTTP signature handler auth", surface, row.ID)
			}
		}
	}
}

func TestRoutePolicyWiring_APIRoutesAreFirstPartySession(t *testing.T) {
	opts := tsrouting.DevOpts()
	for _, row := range tsrouting.RoutesBySurface(opts, service.SurfaceAPI) {
		if row.TrustClass != service.TrustPeerNone {
			t.Errorf("api route %q TrustClass = %q, want peer-trust-none", row.ID, row.TrustClass)
		}
		switch row.HandlerAuth {
		case service.HandlerAuthNone,
			service.HandlerAuthCurrentUser,
			service.HandlerAuthRateLimitOnly:
		default:
			t.Errorf("api route %q HandlerAuth = %q, want first-party session handler auth", row.ID, row.HandlerAuth)
		}
	}
}

func TestRoutePolicyWiring_APIOutboundKinds(t *testing.T) {
	opts := tsrouting.DevOpts()
	found := make(map[service.OutboundProtocolKind]bool)
	for _, kind := range tsrouting.KnownOutboundKinds() {
		found[kind] = false
	}

	for _, row := range tsrouting.RoutesBySurface(opts, service.SurfaceAPI) {
		if row.OutboundProtocolKind == service.OutboundNone {
			continue
		}
		if !tsrouting.IsKnownOutboundKind(row.OutboundProtocolKind) {
			t.Errorf("api route %q unknown OutboundProtocolKind %q", row.ID, row.OutboundProtocolKind)
		}
		found[row.OutboundProtocolKind] = true
	}

	for kind, ok := range found {
		if !ok {
			t.Errorf("expected api route with outbound kind %q", kind)
		}
	}
}

func TestRoutePolicyWiring_WebDAVUsesHandlerAuthNotSession(t *testing.T) {
	opts := tsrouting.DevOpts()
	rows := tsrouting.RoutesBySurface(opts, service.SurfaceWebDAV)
	if len(rows) == 0 {
		t.Fatal("expected webdav product routes")
	}
	for _, row := range rows {
		if row.HandlerAuth != service.HandlerAuthBearer {
			t.Errorf("webdav route %q HandlerAuth = %q, want bearer", row.ID, row.HandlerAuth)
		}
		if row.SessionPolicy != service.SessionPublic {
			t.Errorf("webdav route %q SessionPolicy = %q, want public (handler-authenticated)", row.ID, row.SessionPolicy)
		}
		if row.TrustClass != service.TrustPeerNone {
			t.Errorf("webdav route %q TrustClass = %q, want peer-trust-none", row.ID, row.TrustClass)
		}
	}
}

func TestRoutePolicyWiring_InviteAcceptDialogDistinctFromInviteAccepted(t *testing.T) {
	opts := tsrouting.InviteAcceptEnabledOpts()
	var uiAccept, ocmInvite *service.RouteRow
	for _, row := range tsrouting.ProductRoutes(opts) {
		switch row.ID {
		case service.RouteIDUIAcceptInvite:
			copy := row
			uiAccept = &copy
		case "ocm-invite-accepted":
			copy := row
			ocmInvite = &copy
		}
	}
	if uiAccept == nil {
		t.Fatal("missing ui-accept-invite product route when invite accept enabled")
	}
	if ocmInvite == nil {
		t.Fatal("missing ocm-invite-accepted product route")
	}

	if !tsrouting.HasDiscoveryField(*uiAccept, "inviteAcceptDialog") {
		t.Errorf("ui-accept-invite missing inviteAcceptDialog discovery field: %v", uiAccept.DiscoveryFields)
	}
	if tsrouting.HasDiscoveryField(*ocmInvite, "inviteAcceptDialog") {
		t.Errorf("ocm-invite-accepted must not carry inviteAcceptDialog discovery field")
	}

	if uiAccept.FullPath == ocmInvite.FullPath {
		t.Fatalf("ui accept and ocm invite-accepted share FullPath %q", uiAccept.FullPath)
	}
	if uiAccept.FullPath != "/ui/accept-invite" {
		t.Errorf("ui-accept-invite FullPath = %q, want /ui/accept-invite", uiAccept.FullPath)
	}
	if ocmInvite.FullPath != "/ocm/invite-accepted" {
		t.Errorf("ocm-invite-accepted FullPath = %q, want /ocm/invite-accepted", ocmInvite.FullPath)
	}

	if uiAccept.SurfaceClass != service.SurfaceUI {
		t.Errorf("ui-accept-invite surface = %q, want ui", uiAccept.SurfaceClass)
	}
	if ocmInvite.SurfaceClass != service.SurfaceProtocol {
		t.Errorf("ocm-invite-accepted surface = %q, want protocol", ocmInvite.SurfaceClass)
	}
}
