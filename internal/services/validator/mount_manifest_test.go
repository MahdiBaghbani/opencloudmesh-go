// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validator

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/passive"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestMountPlaneARoutes_ManifestAnonymousGET(t *testing.T) {
	t.Parallel()

	store := openMountTestStore(t)
	passiveHandler := passive.NewHandler(store, nil)

	r := chi.NewRouter()
	mountPlaneARoutes(r, passiveHandler, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteAPIManifest, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["schema"] != "federation_tester_manifest.v1" {
		t.Fatalf("schema = %v, want federation_tester_manifest.v1", payload["schema"])
	}
}

func TestRouteSpecs_ManifestPublicAnonymous(t *testing.T) {
	t.Parallel()

	enabled := service.RouteOpts{
		ValidatorEnabled:  true,
		TokenExchangePath: "token",
	}

	var manifestSpec *service.RouteSpec

	for _, spec := range service.RegisteredRouteSpecs(enabled) {
		if spec.Pattern == RouteAPIManifest {
			manifestSpec = &spec

			break
		}
	}

	if manifestSpec == nil {
		t.Fatal("expected manifest route spec")
	}

	if manifestSpec.SessionPolicy != service.SessionPublic {
		t.Fatalf("SessionPolicy = %q, want public", manifestSpec.SessionPolicy)
	}

	if manifestSpec.HandlerAuth != service.HandlerAuthNone {
		t.Fatalf("HandlerAuth = %q, want none", manifestSpec.HandlerAuth)
	}

	if service.SessionAuthRequiredForPath("/validator/api/manifest", enabled) {
		t.Fatal("expected anonymous access to /validator/api/manifest")
	}
}

func TestValidatorService_MountsManifestRoute(t *testing.T) {
	t.Parallel()

	store := openMountTestStore(t)

	svc, err := New(Inputs{
		Store: store,
		Ratelimit: ratelimit.Inputs{
			KeyFunc: func(*http.Request) string { return "k" },
		},
		Log: slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError})),
	}, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteAPIManifest, nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestMountPlaneARoutes_ManifestRoutesMatchAdvertised(t *testing.T) {
	t.Parallel()

	store := openMountTestStore(t)
	passiveHandler := passive.NewHandler(store, nil)

	r := chi.NewRouter()
	mountPlaneARoutes(r, passiveHandler, nil)

	mounted, err := passive.EnumeratePlaneARoutes(r)
	if err != nil {
		t.Fatalf("EnumeratePlaneARoutes: %v", err)
	}

	mountedSet := make(map[passive.MountedAPIRoute]struct{}, len(mounted))
	for _, route := range mounted {
		mountedSet[route] = struct{}{}
	}

	advertisedSet := make(map[passive.MountedAPIRoute]struct{}, len(passive.MountedAPIRoutes()))
	for _, route := range passive.MountedAPIRoutes() {
		advertisedSet[route] = struct{}{}
	}

	for route := range mountedSet {
		if _, ok := advertisedSet[route]; !ok {
			t.Errorf("mounted route not advertised: method=%s full_path=%s", route.Method, route.FullPath)
		}
	}

	for route := range advertisedSet {
		if _, ok := mountedSet[route]; !ok {
			t.Errorf("advertised route not mounted: method=%s full_path=%s", route.Method, route.FullPath)
		}
	}
}

func TestMountPlaneARoutes_SessionAnonymousGET(t *testing.T) {
	t.Parallel()

	store := openMountTestStore(t)
	passiveHandler := passive.NewHandler(store, nil)
	ctx := t.Context()
	now := int64(1_700_000_000)
	runID := "run-mount-poll"

	row := &validatorcore.TestRun{
		TestRunID:   runID,
		State:       validatorcore.StateCreated,
		SessionKind: validatorcore.SessionKindPassiveOnly,
		TargetHost:  "peer.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := store.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := chi.NewRouter()
	mountPlaneARoutes(r, passiveHandler, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/"+runID, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["state"] != validatorcore.StateCreated {
		t.Fatalf("state = %v, want %q", payload["state"], validatorcore.StateCreated)
	}

	if payload["ts"] != float64(now) {
		t.Fatalf("ts = %v, want %d", payload["ts"], now)
	}
}

func TestRouteSpecs_ManifestGatedByValidatorFeature(t *testing.T) {
	t.Parallel()

	enabled := service.RouteOpts{ValidatorEnabled: true, TokenExchangePath: "token"}
	disabled := service.RouteOpts{ValidatorEnabled: false, TokenExchangePath: "token"}

	if !routeSpecPresent(t, enabled, RouteAPIManifest) {
		t.Fatal("expected manifest route when validator enabled")
	}

	if routeSpecPresent(t, disabled, RouteAPIManifest) {
		t.Fatal("manifest route must be absent when validator disabled")
	}
}

func routeSpecPresent(t *testing.T, opts service.RouteOpts, pattern string) bool {
	t.Helper()

	for _, spec := range service.RegisteredRouteSpecs(opts) {
		if spec.Pattern == pattern {
			return true
		}
	}

	return false
}
