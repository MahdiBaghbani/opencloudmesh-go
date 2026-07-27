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
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/routing"
)

func TestGetMountSpecs_FromDerivedProjection(t *testing.T) {
	groups := GetMountSpecs()
	if len(groups) == 0 {
		t.Fatal("expected derived route groups")
	}

	foundWellKnown := false
	foundWellKnownSlash := false
	foundJWKS := false

	for _, rg := range groups {
		if rg.PathPrefix == "/.well-known/ocm" && rg.AtHostRoot {
			foundWellKnown = true
		}

		if rg.PathPrefix == "/.well-known/ocm/" && rg.AtHostRoot {
			foundWellKnownSlash = true
		}

		if rg.PathPrefix == "/.well-known/jwks.json" && rg.AtHostRoot {
			foundJWKS = true
		}
	}

	if !foundWellKnown {
		t.Error("expected /.well-known/ocm host-root group")
	}

	if !foundWellKnownSlash {
		t.Error("expected /.well-known/ocm/ host-root group")
	}

	if !foundJWKS {
		t.Error("expected /.well-known/jwks.json host-root group")
	}
}

func expectedMountOrder() []string {
	return append([]string{service.RootService}, service.AppServices()...)
}

func expectedShutdownOrder() []string {
	order := expectedMountOrder()
	slices.Reverse(order)

	return order
}

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

func (t *orderTrackingService) Close() error {
	*t.closeOrder = append(*t.closeOrder, t.name)
	return nil
}

func TestRoutesMountOrder(t *testing.T) {
	var mountOrder []string

	srv := newOrderTrackingServer(t, &mountOrder, nil)

	want := expectedMountOrder()
	if !slices.Equal(mountOrder, want) {
		t.Fatalf("mount order = %v, want %v", mountOrder, want)
	}

	_ = srv.Shutdown(context.Background()) //nolint:errcheck // test server cleanup after mount order assertion
}

func TestRoutesShutdownOrder(t *testing.T) {
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

	_ = service.DefaultRouteOpts()

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
