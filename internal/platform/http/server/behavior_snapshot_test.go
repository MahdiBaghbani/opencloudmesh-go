package server

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

type routeGroupSnapshot struct {
	Name         string
	PathPrefix   string
	RequiresAuth bool
	AtHostRoot   bool
}

// snapshotRouteGroups is the Q5 T0 auth/routing table from routes.go.
var snapshotRouteGroups = []routeGroupSnapshot{
	{Name: "well-known-ocm", PathPrefix: "/.well-known/ocm", RequiresAuth: false, AtHostRoot: true},
	{Name: "ocm-provider", PathPrefix: "/ocm-provider", RequiresAuth: false, AtHostRoot: true},
	{Name: "ocm-api", PathPrefix: "/ocm", RequiresAuth: false, AtHostRoot: false},
	{Name: "ocm-aux", PathPrefix: "/ocm-aux", RequiresAuth: false, AtHostRoot: false},
	{Name: "api", PathPrefix: "/api", RequiresAuth: true, AtHostRoot: false},
	{Name: "ui", PathPrefix: "/ui", RequiresAuth: true, AtHostRoot: false},
	{Name: "webdav", PathPrefix: "/webdav/ocm", RequiresAuth: false, AtHostRoot: false},
}

// snapshotMountOrder is root service first, then AppServices in CoreServices order.
var snapshotMountOrder = []string{
	"wellknown",
	"ocm",
	"ocmaux",
	"api",
	"ui",
	"webdav",
}

// snapshotShutdownOrder is reverse mount order.
var snapshotShutdownOrder = []string{
	"webdav",
	"ui",
	"api",
	"ocmaux",
	"ocm",
	"wellknown",
}

type authDecisionSnapshot struct {
	name     string
	path     string
	basePath string
	wantAuth bool
}

// snapshotAuthDecisions samples IsAuthRequired against the Q5 T0 mock unprotected sets.
var snapshotAuthDecisions = []authDecisionSnapshot{
	{name: "well-known public", path: "/.well-known/ocm", basePath: "", wantAuth: false},
	{name: "ocm-provider public", path: "/ocm-provider", basePath: "", wantAuth: false},
	{name: "healthz public", path: "/api/healthz", basePath: "", wantAuth: false},
	{name: "healthz with base path", path: "/ocm/api/healthz", basePath: "/ocm", wantAuth: false},
	{name: "api protected", path: "/api/users", basePath: "", wantAuth: true},
	{name: "unknown protected", path: "/unknown", basePath: "", wantAuth: true},
}

func TestBehaviorSnapshot_RouteGroupsTable(t *testing.T) {
	got := GetRouteGroups()
	if len(got) != len(snapshotRouteGroups) {
		t.Fatalf("route group count = %d, want %d", len(got), len(snapshotRouteGroups))
	}
	for i, want := range snapshotRouteGroups {
		g := got[i]
		if g.Name != want.Name ||
			g.PathPrefix != want.PathPrefix ||
			g.RequiresAuth != want.RequiresAuth ||
			g.AtHostRoot != want.AtHostRoot {
			t.Errorf("routeGroups[%d] = %+v, want %+v", i, g, want)
		}
	}
}

func TestBehaviorSnapshot_AuthDecisions(t *testing.T) {
	svcs := testServices()
	for _, tc := range snapshotAuthDecisions {
		t.Run(tc.name, func(t *testing.T) {
			got := IsAuthRequired(tc.path, tc.basePath, svcs)
			if got != tc.wantAuth {
				t.Fatalf("IsAuthRequired(%q, %q) authRequired=%v, want %v",
					tc.path, tc.basePath, got, tc.wantAuth)
			}
		})
	}
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

func TestBehaviorSnapshot_MountOrder(t *testing.T) {
	var mountOrder []string
	srv := newSnapshotOrderServer(t, &mountOrder, nil)

	if !slices.Equal(mountOrder, snapshotMountOrder) {
		t.Fatalf("mount order = %v, want %v", mountOrder, snapshotMountOrder)
	}

	_ = srv.Shutdown(context.Background())
}

func TestBehaviorSnapshot_ShutdownOrder(t *testing.T) {
	var closeOrder []string
	srv := newSnapshotOrderServer(t, nil, &closeOrder)

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	if !slices.Equal(closeOrder, snapshotShutdownOrder) {
		t.Fatalf("shutdown order = %v, want %v", closeOrder, snapshotShutdownOrder)
	}
}

func TestBehaviorSnapshot_MountOrderRoutesSourceAnchor(t *testing.T) {
	root := moduleRootForSnapshot(t)
	routesPath := filepath.Join(root, "internal/platform/http/server/routes.go")
	body, err := os.ReadFile(routesPath)
	if err != nil {
		t.Fatalf("read routes.go: %v", err)
	}
	text := string(body)

	for _, needle := range []string{
		`s.mountService(r, s.services[service.RootService], true)`,
		`for _, name := range service.AppServices() {`,
		`s.mountService(r, s.services[name], false)`,
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("routes.go mount-order anchor missing %q", needle)
		}
	}
}

func newSnapshotOrderServer(t *testing.T, mountOrder, closeOrder *[]string) *Server {
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

	services := make(map[string]service.Service, len(snapshotMountOrder))
	for _, name := range snapshotMountOrder {
		prefix := servicePrefixForSnapshot(name)
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

func moduleRootForSnapshot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find module root (go.mod)")
		}
		dir = parent
	}
}

func servicePrefixForSnapshot(name string) string {
	switch name {
	case service.RootService:
		return ""
	case "ocmaux":
		return "ocm-aux"
	default:
		return name
	}
}
