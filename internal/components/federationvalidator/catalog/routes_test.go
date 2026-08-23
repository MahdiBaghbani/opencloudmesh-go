// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package catalog

import (
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRoutes_ContainsAbortAndClaim(t *testing.T) {
	t.Parallel()

	if _, ok := Lookup(service.RouteIDValidatorAPISessionAbort); !ok {
		t.Fatal("catalog missing abort route")
	}

	if _, ok := Lookup(service.RouteIDValidatorAPISessionInvite); !ok {
		t.Fatal("catalog missing claim route")
	}
}

func TestRoutes_ScanUsesRateLimitWrap(t *testing.T) {
	t.Parallel()

	def, ok := Lookup(service.RouteIDValidatorAPIScan)
	if !ok {
		t.Fatal("catalog missing scan route")
	}

	if def.HandlerAuth != service.HandlerAuthRateLimitOnly {
		t.Fatalf("scan HandlerAuth = %q, want rate limit only", def.HandlerAuth)
	}

	if len(def.Middleware) != 1 || def.Middleware[0] != MiddlewareRateLimit {
		t.Fatalf("scan Middleware = %v, want [%s]", def.Middleware, MiddlewareRateLimit)
	}
}

func TestRoutes_PasteUsesRateLimitMetadata(t *testing.T) {
	t.Parallel()

	def, ok := Lookup(service.RouteIDValidatorAPISessionReverseInvite)
	if !ok {
		t.Fatal("catalog missing paste route")
	}

	if def.HandlerAuth != service.HandlerAuthRateLimitOnly {
		t.Fatalf("paste HandlerAuth = %q, want rate limit only", def.HandlerAuth)
	}

	if len(def.Middleware) != 1 || def.Middleware[0] != MiddlewareRateLimit {
		t.Fatalf("paste Middleware = %v, want [%s]", def.Middleware, MiddlewareRateLimit)
	}
}

func TestRoutes_MountWhenEmptyAndFull(t *testing.T) {
	t.Parallel()

	empty := Caps{}
	full := FullCaps()

	var emptyMounted, fullMounted int

	for _, def := range Routes() {
		if def.ShouldMount(empty) {
			emptyMounted++
		}

		if def.ShouldMount(full) {
			fullMounted++
		}
	}

	if emptyMounted >= fullMounted {
		t.Fatalf("empty mounted %d, full mounted %d; full must mount more", emptyMounted, fullMounted)
	}

	scan, _ := Lookup(service.RouteIDValidatorAPIScan)
	if scan.ShouldMount(empty) {
		t.Fatal("scan must not mount when capabilities are empty")
	}

	if !scan.ShouldMount(full) {
		t.Fatal("scan must mount when capabilities are full")
	}

	abort, _ := Lookup(service.RouteIDValidatorAPISessionAbort)
	if abort.ShouldMount(empty) {
		t.Fatal("abort must not mount when capabilities are empty")
	}

	if !abort.ShouldMount(Caps{Abort: true}) {
		t.Fatal("abort must mount from Abort alone")
	}

	startPage, _ := Lookup(service.RouteIDValidatorHTMLStart)
	if startPage.ShouldMount(empty) {
		t.Fatal("start page must not mount when capabilities are empty")
	}

	claim, _ := Lookup(service.RouteIDValidatorAPISessionInvite)

	paste, _ := Lookup(service.RouteIDValidatorAPISessionReverseInvite)
	if claim.ShouldMount(empty) || paste.ShouldMount(empty) {
		t.Fatal("claim and paste must not mount when capabilities are empty")
	}

	if !claim.ShouldMount(full) || !paste.ShouldMount(full) {
		t.Fatal("claim and paste must mount when reverse invite is available")
	}
}

func TestRouteSpecs_ProjectsCatalog(t *testing.T) {
	t.Parallel()

	specs := RouteSpecs()
	if len(specs) != len(Routes()) {
		t.Fatalf("RouteSpecs len = %d, want %d", len(specs), len(Routes()))
	}

	for i, spec := range specs {
		if spec.Method == http.MethodGet && spec.Pattern == PatternStart {
			if spec.ID != service.RouteIDValidatorHTMLStart {
				t.Fatalf("GET start ID = %q", spec.ID)
			}

			if spec.SurfaceClass != service.SurfaceUI {
				t.Fatalf("GET start surface = %q", spec.SurfaceClass)
			}
		}

		if spec.ID != Routes()[i].ID {
			t.Fatalf("spec[%d] ID = %q, want %q", i, spec.ID, Routes()[i].ID)
		}
	}
}
