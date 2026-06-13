package server

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

type routeGroupExpectation struct {
	Name         string
	PathPrefix   string
	RequiresAuth bool
	AtHostRoot   bool
}

func expectedRouteGroups() []routeGroupExpectation {
	specs := service.RouteGroupsFromDescriptors()
	out := make([]routeGroupExpectation, len(specs))
	for i, spec := range specs {
		out[i] = routeGroupExpectation{
			Name:         spec.Name,
			PathPrefix:   spec.PathPrefix,
			RequiresAuth: spec.RequiresAuth,
			AtHostRoot:   spec.AtHostRoot,
		}
	}
	return out
}

type authDecisionCase struct {
	name     string
	path     string
	basePath string
	wantAuth bool
}

var authDecisionCases = []authDecisionCase{
	{name: "well-known public", path: "/.well-known/ocm", basePath: "", wantAuth: false},
	{name: "ocm-provider public", path: "/ocm-provider", basePath: "", wantAuth: false},
	{name: "healthz public", path: "/api/healthz", basePath: "", wantAuth: false},
	{name: "healthz with base path", path: "/ocm/api/healthz", basePath: "/ocm", wantAuth: false},
	{name: "api protected", path: "/api/users", basePath: "", wantAuth: true},
	{name: "unknown protected", path: "/unknown", basePath: "", wantAuth: true},
}

func expectedMountOrder() []string {
	return append([]string{service.RootService}, service.AppServices()...)
}

func expectedShutdownOrder() []string {
	order := expectedMountOrder()
	slices.Reverse(order)
	return order
}

// orderTrackingService records mount order via Handler() and shutdown via Close().
type orderTrackingService struct {
	name       string
	prefix     string
	mountOrder *[]string
	closeOrder *[]string
}

func (t *orderTrackingService) Handler() http.Handler {
	*t.mountOrder = append(*t.mountOrder, t.name)
	return http.NotFoundHandler()
}

func (t *orderTrackingService) Prefix() string { return t.prefix }

func (t *orderTrackingService) Unprotected() []string { return nil }

func (t *orderTrackingService) Close() error {
	*t.closeOrder = append(*t.closeOrder, t.name)
	return nil
}

func TestRoutesContract_RouteGroupsTable(t *testing.T) {
	got := GetRouteGroups()
	want := expectedRouteGroups()
	if len(got) != len(want) {
		t.Fatalf("route group count = %d, want %d", len(got), len(want))
	}
	for i, want := range want {
		g := got[i]
		if g.Name != want.Name ||
			g.PathPrefix != want.PathPrefix ||
			g.RequiresAuth != want.RequiresAuth ||
			g.AtHostRoot != want.AtHostRoot {
			t.Errorf("routeGroups[%d] = %+v, want %+v", i, g, want)
		}
	}
}

func TestRoutesContract_AuthDecisions(t *testing.T) {
	svcs := testServices()
	for _, tc := range authDecisionCases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsAuthRequired(tc.path, tc.basePath, svcs)
			if got != tc.wantAuth {
				t.Fatalf("IsAuthRequired(%q, %q) authRequired=%v, want %v",
					tc.path, tc.basePath, got, tc.wantAuth)
			}
		})
	}
}

func TestRoutesContract_MountOrder(t *testing.T) {
	var mountOrder []string
	srv := newOrderTrackingServer(t, &mountOrder, nil)

	want := expectedMountOrder()
	if !slices.Equal(mountOrder, want) {
		t.Fatalf("mount order = %v, want %v", mountOrder, want)
	}

	_ = srv.Shutdown(context.Background())
}

func TestRoutesContract_ShutdownOrder(t *testing.T) {
	var closeOrder []string
	srv := newOrderTrackingServer(t, nil, &closeOrder)

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	want := expectedShutdownOrder()
	if !slices.Equal(closeOrder, want) {
		t.Fatalf("shutdown order = %v, want %v", closeOrder, want)
	}
}

func newOrderTrackingServer(t *testing.T, mountOrder, closeOrder *[]string) *Server {
	t.Helper()

	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	if mountOrder == nil {
		empty := []string{}
		mountOrder = &empty
	}
	if closeOrder == nil {
		empty := []string{}
		closeOrder = &empty
	}

	mountOrderNames := expectedMountOrder()
	services := make(map[string]service.Service, len(mountOrderNames))
	for _, name := range mountOrderNames {
		prefix := servicePrefixForOrderTest(name)
		services[name] = &orderTrackingService{
			name:       name,
			prefix:     prefix,
			mountOrder: mountOrder,
			closeOrder: closeOrder,
		}
	}

	srv, err := New(cfg, logger, services, testServerDeps(t, cfg, logger))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return srv
}

func servicePrefixForOrderTest(name string) string {
	desc, ok := service.DescriptorByName(name)
	if !ok {
		return name
	}
	return desc.Prefix
}
