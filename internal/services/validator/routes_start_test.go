// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validator

import (
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRouteSpecs_StartPagePublicUI(t *testing.T) {
	t.Parallel()

	enabled := service.RouteOpts{
		ValidatorEnabled:  true,
		TokenExchangePath: "token",
	}

	spec := findValidatorSpecByMethod(t, enabled, http.MethodGet, RouteHTMLStart)
	if spec.ID != service.RouteIDValidatorHTMLStart {
		t.Fatalf("ID = %q, want %q", spec.ID, service.RouteIDValidatorHTMLStart)
	}

	if spec.SessionPolicy != service.SessionPublic {
		t.Fatalf("SessionPolicy = %q, want public", spec.SessionPolicy)
	}

	if spec.HandlerAuth != service.HandlerAuthNone {
		t.Fatalf("HandlerAuth = %q, want none", spec.HandlerAuth)
	}

	if spec.SurfaceClass != service.SurfaceUI {
		t.Fatalf("SurfaceClass = %q, want ui", spec.SurfaceClass)
	}

	if spec.FeatureCondition != service.FeatureValidatorEnabled {
		t.Fatalf("FeatureCondition = %q", spec.FeatureCondition)
	}

	post := findValidatorSpecByMethod(t, enabled, http.MethodPost, RouteStartCreateSession)
	if post.ID != "validator-start-create-session" {
		t.Fatalf("POST start ID = %q", post.ID)
	}

	if post.SurfaceClass != service.SurfaceAPI {
		t.Fatalf("POST start SurfaceClass = %q, want api", post.SurfaceClass)
	}

	if service.SessionAuthRequiredForPath("/validator/start", enabled) {
		t.Fatal("expected anonymous access to /validator/start")
	}
}

func TestRouteSpecs_StartPageGatedByValidatorFeature(t *testing.T) {
	t.Parallel()

	enabled := service.RouteOpts{ValidatorEnabled: true, TokenExchangePath: "token"}
	disabled := service.RouteOpts{ValidatorEnabled: false, TokenExchangePath: "token"}

	if !routeSpecPresentMethod(t, enabled, http.MethodGet, RouteHTMLStart) {
		t.Fatal("expected GET start page when validator enabled")
	}

	if routeSpecPresentMethod(t, disabled, http.MethodGet, RouteHTMLStart) {
		t.Fatal("GET start page must be absent when validator disabled")
	}
}

func findValidatorSpecByMethod(
	t *testing.T,
	opts service.RouteOpts,
	method, pattern string,
) service.RouteSpec {
	t.Helper()

	for _, spec := range service.RegisteredRouteSpecs(opts) {
		if spec.Service == string(service.BuildValidator) &&
			spec.Pattern == pattern &&
			spec.Method == method {
			return spec
		}
	}

	t.Fatalf("expected validator spec for %s %q", method, pattern)

	return service.RouteSpec{}
}

func routeSpecPresentMethod(t *testing.T, opts service.RouteOpts, method, pattern string) bool {
	t.Helper()

	for _, spec := range service.RegisteredRouteSpecs(opts) {
		if spec.Pattern == pattern && spec.Method == method {
			return true
		}
	}

	return false
}
