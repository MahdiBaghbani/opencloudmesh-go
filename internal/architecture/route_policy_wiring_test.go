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
	groups := service.DerivedRouteGroups(opts)
	inventory := service.DerivedRouteInventory(opts)

	if len(authRows) != len(routes) {
		t.Fatalf("DerivedAuthRows count = %d, Routes count = %d", len(authRows), len(routes))
	}
	if len(groups) == 0 {
		t.Fatal("DerivedRouteGroups returned no groups")
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
