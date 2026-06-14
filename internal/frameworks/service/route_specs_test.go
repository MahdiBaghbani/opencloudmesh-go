package service_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/api"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocmaux"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/wellknown"
)

func TestRegisteredRouteSpecs_IncludesAllCoreServices(t *testing.T) {
	opts := service.DefaultRouteOpts()
	specs := service.RegisteredRouteSpecs(opts)
	if len(specs) == 0 {
		t.Fatal("expected registered route specs")
	}

	seen := make(map[string]struct{})
	for _, spec := range specs {
		if spec.ID == "" {
			t.Errorf("route spec missing ID: %+v", spec)
		}
		if spec.Service == "" {
			t.Errorf("route spec %q missing Service", spec.ID)
		}
		if spec.Pattern == "" {
			t.Errorf("route spec %q missing Pattern", spec.ID)
		}
		if spec.SurfaceClass == "" {
			t.Errorf("route spec %q missing SurfaceClass", spec.ID)
		}
		if spec.HandlerAuth == "" {
			t.Errorf("route spec %q missing HandlerAuth", spec.ID)
		}
		if spec.TrustClass == "" {
			t.Errorf("route spec %q missing TrustClass", spec.ID)
		}
		seen[spec.Service] = struct{}{}
	}

	for _, name := range service.CoreServices {
		if _, ok := seen[name]; !ok {
			t.Errorf("no registered route specs for core service %q", name)
		}
	}
}

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
		if row.HandlerAuth != service.HandlerAuthOptionalHTTPSig {
			t.Errorf("protocol route %q HandlerAuth = %q, want optional HTTP signature", row.ID, row.HandlerAuth)
		}
	}
}

func TestRoutes_APIOutboundKindsDeclaredOnAPIRows(t *testing.T) {
	opts := service.DefaultRouteOpts()
	found := map[service.OutboundProtocolKind]bool{
		service.OutboundNotifications: false,
		service.OutboundShares:        false,
		service.OutboundInvites:       false,
		service.OutboundAccess:        false,
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

func TestDerivedAuthRows_ProjectsFromRoutes(t *testing.T) {
	opts := service.DefaultRouteOpts()
	rows := service.Routes(opts)
	authRows := service.DerivedAuthRows(opts)
	if len(authRows) != len(rows) {
		t.Fatalf("auth row count = %d, route count = %d", len(authRows), len(rows))
	}
}

func TestDerivedRouteGroups_ProjectsFromRoutes(t *testing.T) {
	opts := service.DefaultRouteOpts()
	rows := service.Routes(opts)
	groups := service.DerivedRouteGroups(opts)
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

func TestRouteOptsFromConfig_DevDefaults(t *testing.T) {
	opts := service.RouteOptsFromConfig(nil)
	if opts.TokenExchangePath != "token" {
		t.Errorf("TokenExchangePath = %q, want token", opts.TokenExchangePath)
	}
}

func TestRouteOptsFromConfig_NonNilBranches(t *testing.T) {
	tests := []struct {
		name            string
		cfg             *config.Config
		want            service.RouteOpts
		assertAuthPaths func(t *testing.T, opts service.RouteOpts)
	}{
		{
			name: "external base path",
			cfg: &config.Config{
				ExternalBasePath: "/ocm",
			},
			want: service.RouteOpts{
				ExternalBasePath:    "/ocm",
				WayfEnabled:         false,
				InviteAcceptEnabled: false,
				TokenExchangePath:   "token",
			},
			assertAuthPaths: func(t *testing.T, opts service.RouteOpts) {
				t.Helper()
				if service.SessionAuthRequiredForPath("/ocm/api/healthz", opts) {
					t.Error("expected /ocm/api/healthz public with external base path")
				}
			},
		},
		{
			name: "WAYF enabled via ui service config",
			cfg: &config.Config{
				HTTP: config.HTTPConfig{
					Services: map[string]map[string]any{
						"ui": {
							"wayf": map[string]any{"enabled": true},
						},
					},
				},
			},
			want: service.RouteOpts{
				ExternalBasePath:    "",
				WayfEnabled:         true,
				InviteAcceptEnabled: true,
				TokenExchangePath:   "token",
			},
			assertAuthPaths: func(t *testing.T, opts service.RouteOpts) {
				t.Helper()
				if service.SessionAuthRequiredForPath("/ui/wayf", opts) {
					t.Error("expected /ui/wayf public when WAYF enabled")
				}
				if !service.SessionAuthRequiredForPath("/ui/accept-invite", opts) {
					t.Error("expected /ui/accept-invite protected when invite accept enabled")
				}
			},
		},
		{
			name: "ocm token path from service config takes precedence",
			cfg: &config.Config{
				HTTP: config.HTTPConfig{
					Services: map[string]map[string]any{
						"ocm": {
							"token_exchange": map[string]any{"path": "custom-token"},
						},
					},
				},
				TokenExchange: config.TokenExchangeConfig{Path: "fallback-token"},
			},
			want: service.RouteOpts{
				ExternalBasePath:    "",
				WayfEnabled:         false,
				InviteAcceptEnabled: false,
				TokenExchangePath:   "custom-token",
			},
		},
		{
			name: "token path falls back to top-level config",
			cfg: &config.Config{
				TokenExchange: config.TokenExchangeConfig{Path: "fallback-token"},
			},
			want: service.RouteOpts{
				ExternalBasePath:    "",
				WayfEnabled:         false,
				InviteAcceptEnabled: false,
				TokenExchangePath:   "fallback-token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := service.RouteOptsFromConfig(tt.cfg)
			if opts != tt.want {
				t.Errorf("RouteOptsFromConfig() = %+v, want %+v", opts, tt.want)
			}
			if tt.assertAuthPaths != nil {
				tt.assertAuthPaths(t, opts)
			}
		})
	}
}

func TestRegisteredRouteSpecs_AllResolveDescriptor(t *testing.T) {
	tests := []struct {
		name string
		opts service.RouteOpts
	}{
		{
			name: "default opts",
			opts: service.DefaultRouteOpts(),
		},
		{
			name: "WAYF-enabled opts",
			opts: service.RouteOpts{
				ExternalBasePath:    "",
				WayfEnabled:         true,
				InviteAcceptEnabled: true,
				TokenExchangePath:   "token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specs := service.RegisteredRouteSpecs(tt.opts)
			for _, spec := range specs {
				if _, ok := service.DescriptorByName(spec.Service); !ok {
					t.Errorf("route spec %q service %q has no descriptor", spec.ID, spec.Service)
				}
			}
		})
	}
}

func TestRouteIDSSOT_StaticTokenAndSubtreeDefault(t *testing.T) {
	if got := service.SubtreeDefaultID("ocm"); got != "ocm-subtree-default" {
		t.Errorf("SubtreeDefaultID(ocm) = %q, want ocm-subtree-default", got)
	}

	tokenPaths := []string{"token", "auth/exchange", "token/v2"}
	for _, tokenPath := range tokenPaths {
		t.Run(tokenPath, func(t *testing.T) {
			opts := service.RouteOpts{TokenExchangePath: tokenPath}
			rows := service.Routes(opts)
			var tokenRow *service.RouteRow
			for i := range rows {
				if rows[i].ID == service.RouteIDOCMToken {
					tokenRow = &rows[i]
					break
				}
			}
			if tokenRow == nil {
				t.Fatalf("Routes(opts) missing token row for path %q", tokenPath)
			}
			if tokenRow.ID != service.RouteIDOCMToken {
				t.Errorf("token row ID = %q, want %q", tokenRow.ID, service.RouteIDOCMToken)
			}
		})
	}
}

func TestDerivedRouteInventory_ExternalBasePath(t *testing.T) {
	opts := service.RouteOpts{
		ExternalBasePath:    "/ocm",
		WayfEnabled:         false,
		InviteAcceptEnabled: false,
		TokenExchangePath:   "token",
	}
	inventory := service.DerivedRouteInventory(opts)

	prefixedServices := map[string]bool{"api": false, "ui": false, "ocm": false}
	for _, row := range inventory {
		if row.MountAtRoot {
			if isRootOnlyDiscoveryPath(row.FullPath) {
				continue
			}
			t.Errorf("unexpected host-root inventory row %q with external base path", row.FullPath)
			continue
		}
		if !hasPrefix(row.FullPath, "/ocm/") && row.FullPath != "/ocm" {
			t.Errorf("inventory row %q FullPath = %q, want /ocm prefix", row.ID, row.FullPath)
		}
		if _, ok := prefixedServices[row.Service]; ok {
			prefixedServices[row.Service] = true
		}
	}
	for svc, seen := range prefixedServices {
		if !seen {
			t.Errorf("missing prefixed inventory row for service %q", svc)
		}
	}

	for _, path := range publicPathsUnderBase(opts) {
		if service.SessionAuthRequiredForPath(path, opts) {
			t.Errorf("expected public path %q under external base", path)
		}
	}
}

func hasPrefix(path, prefix string) bool {
	return len(path) >= len(prefix) && path[:len(prefix)] == prefix
}

func isRootOnlyDiscoveryPath(path string) bool {
	return path == "/.well-known/ocm" ||
		path == "/.well-known/ocm/" ||
		path == "/ocm-provider" ||
		path == "/ocm-provider/"
}

func publicPathsUnderBase(opts service.RouteOpts) []string {
	rows := service.DerivedRouteInventory(opts)
	var paths []string
	for _, row := range rows {
		if row.SessionPolicy != service.SessionPublic {
			continue
		}
		if !row.MountAtRoot && !hasPrefix(row.FullPath, "/ocm/") {
			continue
		}
		paths = append(paths, row.FullPath)
	}
	return paths
}
