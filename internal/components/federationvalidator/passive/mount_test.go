// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
)

func newPlaneATestRouter(t *testing.T) chi.Router {
	t.Helper()

	r := chi.NewRouter()
	h := NewHandler(openHandlerTestStore(t), nil)
	h.SetCaps(catalog.FullCaps())
	MountPlaneARoutes(r, h, nil)

	return r
}

func TestMountPlaneARoutes_ClaimUsesSharedStartLimiter(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32

	limiter := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)

			next.ServeHTTP(w, r)
		})
	}

	r := chi.NewRouter()
	h := NewHandler(openHandlerTestStore(t), nil)
	h.SetCaps(catalog.FullCaps())
	MountPlaneARoutes(r, h, limiter)

	startReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteStartCreateSession, nil)
	r.ServeHTTP(httptest.NewRecorder(), startReq)

	claimReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/session/run-1/invite", nil)
	r.ServeHTTP(httptest.NewRecorder(), claimReq)

	if got := hits.Load(); got != 2 {
		t.Fatalf("shared limiter hits = %d, want 2", got)
	}
}

func TestMountPlaneARoutes_ScanUsesSharedStartLimiter(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32

	limiter := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)

			next.ServeHTTP(w, r)
		})
	}

	r := chi.NewRouter()
	h := NewHandler(openHandlerTestStore(t), nil)
	h.SetCaps(catalog.FullCaps())
	MountPlaneARoutes(r, h, limiter)

	scanReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"/api/scan?target=https://peer.example",
		nil,
	)
	r.ServeHTTP(httptest.NewRecorder(), scanReq)

	if got := hits.Load(); got != 1 {
		t.Fatalf("scan limiter hits = %d, want 1", got)
	}
}

func TestMountPlaneARoutes_UnlimitedRoutesSkipSharedLimiter(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32

	limiter := func(_ http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusTooManyRequests)
		})
	}

	r := chi.NewRouter()
	h := NewHandler(openHandlerTestStore(t), nil)
	h.SetCaps(catalog.FullCaps())
	MountPlaneARoutes(r, h, limiter)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/session/run-1"},
		{method: http.MethodGet, path: RouteAPIManifest},
		{method: http.MethodPost, path: "/api/session/run-1/abort"},
		{method: http.MethodGet, path: RouteAPIStatistics},
		{method: http.MethodPost, path: RouteStopSession},
	} {
		req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("%s %s status = 429, want unlimited", tc.method, tc.path)
		}
	}

	if got := hits.Load(); got != 0 {
		t.Fatalf("unlimited route limiter hits = %d, want 0", got)
	}
}

func TestMountPlaneARoutes_AbortWithoutReverseInvite(t *testing.T) {
	t.Parallel()

	r := chi.NewRouter()
	h := NewHandler(openHandlerTestStore(t), nil)
	h.SetCaps(catalog.Caps{Abort: true})
	MountPlaneARoutes(r, h, nil)

	mounted := mountedRouteSet(t, r)
	hasAbort := false

	for route := range mounted {
		if route.Method == http.MethodPost && strings.HasSuffix(route.FullPath, "/abort") {
			hasAbort = true
		}
	}

	if !hasAbort {
		t.Fatal("abort must mount from Abort alone")
	}

	scanReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/scan?target=https://peer.example", nil)
	scanRec := httptest.NewRecorder()
	r.ServeHTTP(scanRec, scanReq)

	if scanRec.Code != http.StatusNotFound {
		t.Fatalf("scan status = %d, want 404 when reverse invite is unavailable", scanRec.Code)
	}
}

func mountedRouteSet(t *testing.T, r chi.Router) map[MountedAPIRoute]struct{} {
	t.Helper()

	enumerated, err := EnumeratePlaneARoutes(r)
	if err != nil {
		t.Fatalf("EnumeratePlaneARoutes: %v", err)
	}

	return routeListToSet(enumerated)
}

func advertisedRouteSet(routes []MountedAPIRoute) map[MountedAPIRoute]struct{} {
	return routeListToSet(routes)
}

func planeAAdvertised(routes []MountedAPIRoute) []MountedAPIRoute {
	out := make([]MountedAPIRoute, 0, len(routes))

	for _, route := range routes {
		if strings.HasSuffix(route.FullPath, "/reverse-invite") {
			continue
		}

		out = append(out, route)
	}

	return out
}

func routeListToSet(routes []MountedAPIRoute) map[MountedAPIRoute]struct{} {
	set := make(map[MountedAPIRoute]struct{}, len(routes))

	for _, route := range routes {
		set[route] = struct{}{}
	}

	return set
}

func assertSymmetricRouteSets(t *testing.T, mounted, advertised map[MountedAPIRoute]struct{}) {
	t.Helper()

	for route := range mounted {
		if _, ok := advertised[route]; !ok {
			t.Errorf("mounted route not advertised: method=%s full_path=%s", route.Method, route.FullPath)
		}
	}

	for route := range advertised {
		if _, ok := mounted[route]; !ok {
			t.Errorf("advertised route not mounted: method=%s full_path=%s", route.Method, route.FullPath)
		}
	}
}
