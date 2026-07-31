// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package resolve_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
)

func TestResolve_ProjectsFromRouteInventory(t *testing.T) {
	c := &resolve.ProviderConfig{}
	opts := service.RouteOpts{
		ExternalBasePath:    "/ocm",
		TokenExchangePath:   "auth/exchange",
		WayfEnabled:         true,
		InviteAcceptEnabled: true,
		InvitesEnabled:      true,
	}
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
		RouteOpts:     opts,
	}

	built := resolve.Resolve(c, map[string]any{}, in)

	if built.Params.EndPoint != "https://cloud.example.com/ocm/ocm" {
		t.Errorf("EndPoint = %q", built.Params.EndPoint)
	}

	if built.Params.WebDAVRoot != "/ocm/webdav/ocm/" {
		t.Errorf("WebDAVRoot = %q", built.Params.WebDAVRoot)
	}

	if built.Params.TokenEndPoint != "https://cloud.example.com/ocm/ocm/auth/exchange" {
		t.Errorf("TokenEndPoint = %q", built.Params.TokenEndPoint)
	}

	if built.Params.InviteAcceptDialog != "https://cloud.example.com/ocm/ui/accept-invite" {
		t.Errorf("InviteAcceptDialog = %q", built.Params.InviteAcceptDialog)
	}

	if !built.Params.WayfEnabled {
		t.Fatal("expected WayfEnabled from route opts")
	}
}

func TestResolve_InviteAcceptIndependentFromWAYF(t *testing.T) {
	c := &resolve.ProviderConfig{}
	opts := service.RouteOpts{
		ExternalBasePath:    "/ocm",
		InviteAcceptEnabled: true,
		InvitesEnabled:      true,
		WayfEnabled:         false,
	}
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
		RouteOpts:     opts,
	}

	built := resolve.Resolve(c, map[string]any{}, in)

	if built.Params.WayfEnabled {
		t.Fatal("test precondition: WayfEnabled must be false")
	}

	if built.Params.InviteAcceptDialog == "" {
		t.Fatal("expected non-empty inviteAcceptDialog from ui-accept-invite route")
	}

	disc := discovery.BuildDiscovery(built.Params, nil)
	if disc.InviteAcceptDialog == "" {
		t.Error("expected inviteAcceptDialog in discovery document")
	}

	if !disc.HasCapability("invites") {
		t.Error("expected invites capability when InvitesEnabled is true")
	}

	if disc.HasCapability("invite-wayf") {
		t.Error("invite-wayf capability must not be added when WAYF route is inactive")
	}
}
