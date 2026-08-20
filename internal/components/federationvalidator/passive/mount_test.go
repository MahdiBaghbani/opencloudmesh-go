// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"testing"

	"github.com/go-chi/chi/v5"
)

func defaultPlaneAAPIRoutePatterns() PlaneAAPIRoutePatterns {
	return PlaneAAPIRoutePatterns{
		Scan:       RouteAPIScan,
		Session:    RouteAPISession,
		Manifest:   RouteAPIManifest,
		Statistics: RouteAPIStatistics,
		Report:     RouteAPIReport,
	}
}

func newPlaneATestRouter(t *testing.T) chi.Router {
	t.Helper()

	r := chi.NewRouter()
	MountPlaneARoutes(r, NewHandler(openHandlerTestStore(t), nil), nil, defaultPlaneAAPIRoutePatterns())

	return r
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
