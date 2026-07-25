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

func TestDerivedAuthRows_ProjectsFromRoutes(t *testing.T) {
	opts := service.DefaultRouteOpts()
	rows := service.Routes(opts)
	authRows := service.DerivedAuthRows(opts)
	if len(authRows) != len(rows) {
		t.Fatalf("auth row count = %d, route count = %d", len(authRows), len(rows))
	}
}

func TestDerivedMountSpecs_ProjectsFromRoutes(t *testing.T) {
	opts := service.DefaultRouteOpts()
	rows := service.Routes(opts)
	groups := service.DerivedMountSpecs(opts)
	if len(groups) == 0 {
		t.Fatal("expected derived route groups")
	}

	wantHostRoot := 0
	wantSubtree := 0
	for _, row := range rows {
		if row.AtHostRoot && !row.Synthetic {
			wantHostRoot++
		}
		if row.Synthetic && !row.AtHostRoot {
			wantSubtree++
		}
	}
	if len(groups) != wantHostRoot+wantSubtree {
		t.Fatalf("group count = %d, want %d host-root + %d subtree", len(groups), wantHostRoot, wantSubtree)
	}

	byPrefix := make(map[string]service.DerivedRouteGroup, len(groups))
	for _, g := range groups {
		byPrefix[g.PathPrefix] = g
	}

	for _, row := range rows {
		if row.Synthetic && !row.AtHostRoot {
			g, ok := byPrefix[row.FullPath]
			if !ok {
				t.Errorf("missing subtree group for synthetic row %q prefix %q", row.ID, row.FullPath)
				continue
			}
			if g.Name != row.Service {
				t.Errorf("subtree group %q name = %q, want service %q", row.FullPath, g.Name, row.Service)
			}
			if g.AtHostRoot {
				t.Errorf("subtree group %q AtHostRoot = true, want false", row.FullPath)
			}
			wantAuth := service.SessionAuthRequiredForPath(row.FullPath+"/probe", opts)
			if g.RequiresAuth != wantAuth {
				t.Errorf("subtree group %q RequiresAuth = %v, want %v", row.FullPath, g.RequiresAuth, wantAuth)
			}
			continue
		}
		if row.AtHostRoot && !row.Synthetic {
			g, ok := byPrefix[row.FullPath]
			if !ok {
				t.Errorf("missing host-root group for row %q prefix %q", row.ID, row.FullPath)
				continue
			}
			if g.Name != row.ID {
				t.Errorf("host-root group %q name = %q, want id %q", row.FullPath, g.Name, row.ID)
			}
			if !g.AtHostRoot {
				t.Errorf("host-root group %q AtHostRoot = false, want true", row.FullPath)
			}
			wantAuth := service.SessionAuthRequiredForPath(row.FullPath+"/probe", opts)
			if g.RequiresAuth != wantAuth {
				t.Errorf("host-root group %q RequiresAuth = %v, want %v", row.FullPath, g.RequiresAuth, wantAuth)
			}
		}
	}
}

func TestSessionAuthRequiredForPath_PublicAndProtected(t *testing.T) {
	opts := service.DefaultRouteOpts()

	cases := []struct {
		path     string
		wantAuth bool
	}{
		{"/.well-known/ocm", false},
		{"/api/healthz", false},
		{"/api/auth/login", false},
		{"/ui/login", false},
		{"/ocm/shares", false},
		{"/api/inbox/shares", true},
		{"/ui/inbox", true},
		{"/unknown", true},
	}
	for _, tc := range cases {
		got := service.SessionAuthRequiredForPath(tc.path, opts)
		if got != tc.wantAuth {
			t.Errorf("SessionAuthRequiredForPath(%q) = %v, want %v", tc.path, got, tc.wantAuth)
		}
	}
}

func TestSessionAuthRequiredForPath_WayfRoutes(t *testing.T) {
	disabled := service.DefaultRouteOpts()
	if !service.SessionAuthRequiredForPath("/ui/wayf", disabled) {
		t.Error("expected /ui/wayf protected when WAYF disabled")
	}

	enabled := service.RouteOpts{
		WayfEnabled:         true,
		InviteAcceptEnabled: true,
		TokenExchangePath:   "token",
	}
	if service.SessionAuthRequiredForPath("/ui/wayf", enabled) {
		t.Error("expected /ui/wayf public when WAYF enabled")
	}
	if !service.SessionAuthRequiredForPath("/ui/accept-invite", enabled) {
		t.Error("expected /ui/accept-invite protected when invite accept enabled")
	}
}
