// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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
	t.Parallel()

	groups := GetMountSpecs()
	if len(groups) == 0 {
		t.Fatal("expected derived route groups")
	}

	foundWellKnown := false
	foundWellKnownSlash := false
	foundOCMSubtree := false

	for _, rg := range groups {
		if rg.PathPrefix == "/.well-known/ocm" && rg.AtHostRoot {
			foundWellKnown = true
		}

		if rg.PathPrefix == "/.well-known/ocm/" && rg.AtHostRoot {
			foundWellKnownSlash = true
		}

		// The local JWKS route (GET /ocm/jwks) is no longer host-root; it is
		// served under the "ocm" prefixed subtree along with the rest of the
		// OCM protocol routes.
		if rg.PathPrefix == "/ocm" && !rg.AtHostRoot {
			foundOCMSubtree = true
		}
	}

	if !foundWellKnown {
		t.Error("expected /.well-known/ocm host-root group")
	}

	if !foundWellKnownSlash {
		t.Error("expected /.well-known/ocm/ host-root group")
	}

	if !foundOCMSubtree {
		t.Error("expected /ocm prefixed subtree group covering the local JWKS route")
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
	t.Parallel()

	var mountOrder []string

	srv := newOrderTrackingServer(t, &mountOrder, nil)

	want := expectedMountOrder()
	if !slices.Equal(mountOrder, want) {
		t.Fatalf("mount order = %v, want %v", mountOrder, want)
	}

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
}

func TestRoutesShutdownOrder(t *testing.T) {
	t.Parallel()

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
