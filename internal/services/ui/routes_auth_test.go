// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ui

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

// Route-policy tests only: production session enforcement is proven at server
// and integration layers, not by hitting the bare UI service handler.
func TestRouteSpecs_SessionPolicy_WayfAndAcceptInvite(t *testing.T) {
	enabled := service.RouteOpts{
		WayfEnabled:         true,
		InviteAcceptEnabled: true,
		TokenExchangePath:   "token",
	}

	var wayfSpec, acceptSpec *service.RouteSpec

	for _, spec := range service.RegisteredRouteSpecs(enabled) {
		if spec.Service != "ui" {
			continue
		}

		switch spec.Pattern {
		case RouteWAYF:
			wayfSpec = &spec
		case RouteAcceptInvite:
			acceptSpec = &spec
		}
	}

	if wayfSpec == nil || acceptSpec == nil {
		t.Fatal("expected wayf and accept-invite route specs when WAYF enabled")
	}

	if wayfSpec.SessionPolicy != service.SessionPublicWhenWAYF {
		t.Errorf("wayf SessionPolicy = %q, want public when WAYF enabled", wayfSpec.SessionPolicy)
	}

	if acceptSpec.SessionPolicy != service.SessionProtected {
		t.Errorf("accept-invite SessionPolicy = %q, want protected", acceptSpec.SessionPolicy)
	}
}

func TestRouteSpecs_SessionAuthProjection_WayfPublicAcceptInviteProtected(t *testing.T) {
	enabled := service.RouteOpts{
		WayfEnabled:         true,
		InviteAcceptEnabled: true,
		TokenExchangePath:   "token",
	}

	cases := []struct {
		path     string
		wantAuth bool
	}{
		{"/ui/wayf", false},
		{"/ui/accept-invite", true},
		{"/ui/login", false},
	}
	for _, tc := range cases {
		got := service.SessionAuthRequiredForPath(tc.path, enabled)
		if got != tc.wantAuth {
			t.Errorf("SessionAuthRequiredForPath(%q) = %v, want %v", tc.path, got, tc.wantAuth)
		}
	}
}

func TestRouteSpecs_SessionAuthProjection_WithExternalBasePath(t *testing.T) {
	opts := service.RouteOpts{
		ExternalBasePath:    "/ocm",
		WayfEnabled:         true,
		InviteAcceptEnabled: true,
		TokenExchangePath:   "token",
	}

	if service.SessionAuthRequiredForPath("/ocm/ui/wayf", opts) {
		t.Error("expected /ocm/ui/wayf public when WAYF enabled")
	}

	if !service.SessionAuthRequiredForPath("/ocm/ui/accept-invite", opts) {
		t.Error("expected /ocm/ui/accept-invite protected")
	}
}
