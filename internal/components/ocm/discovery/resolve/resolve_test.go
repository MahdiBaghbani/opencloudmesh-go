package resolve_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
)

func TestResolve_AppliesServiceLocalDefaults(t *testing.T) {
	c := &resolve.ProviderConfig{}
	in := resolve.Resolve(c, nil, resolve.ResolveInputs{})

	if c.OCMPrefix != "ocm" {
		t.Errorf("expected OCMPrefix default 'ocm', got %q", c.OCMPrefix)
	}
	if in.Params.Provider != "OpenCloudMesh" {
		t.Errorf("expected Provider default 'OpenCloudMesh', got %q", in.Params.Provider)
	}
}

func TestResolve_DerivesEndPointAndWebDAVRoot(t *testing.T) {
	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
		RouteOpts:     service.RouteOpts{ExternalBasePath: "/ocm"},
	}

	built := resolve.Resolve(c, map[string]any{}, in)

	if built.Params.EndPoint != "https://cloud.example.com/ocm/ocm" {
		t.Errorf("expected derived endPoint, got %q", built.Params.EndPoint)
	}
	if built.Params.WebDAVRoot != "/ocm/webdav/ocm/" {
		t.Errorf("expected derived webdav_root, got %q", built.Params.WebDAVRoot)
	}
}

func TestResolve_SkipsEndPointDerivationWithoutPublicOrigin(t *testing.T) {
	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: localidentity.Identity{ExternalBasePath: "/ocm"},
		RouteOpts:     service.RouteOpts{ExternalBasePath: "/ocm"},
	}

	built := resolve.Resolve(c, map[string]any{}, in)

	if built.Params.EndPoint != "" {
		t.Errorf("expected empty endPoint without Origin, got %q", built.Params.EndPoint)
	}
	if built.Params.WebDAVRoot != "/ocm/webdav/ocm/" {
		t.Errorf("expected derived webdav_root, got %q", built.Params.WebDAVRoot)
	}
}

func TestResolve_RawConfigWinsOverDerivation(t *testing.T) {
	c := &resolve.ProviderConfig{
		Endpoint:   "https://explicit.example.com",
		WebDAVRoot: "/explicit/dav/",
	}
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
		RouteOpts:     service.RouteOpts{ExternalBasePath: "/ocm"},
	}
	raw := map[string]any{
		"endpoint":    "https://explicit.example.com",
		"webdav_root": "/explicit/dav/",
	}

	built := resolve.Resolve(c, raw, in)

	if built.Params.EndPoint != "https://explicit.example.com/ocm" {
		t.Errorf("expected explicit endPoint, got %q", built.Params.EndPoint)
	}
	if built.Params.WebDAVRoot != "/explicit/dav/" {
		t.Errorf("expected explicit webdav_root preserved, got %q", built.Params.WebDAVRoot)
	}
}

func TestResolve_TokenEndPointDefault(t *testing.T) {
	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://example.com", ""),
		RouteOpts:     service.DefaultRouteOpts(),
	}

	built := resolve.Resolve(c, nil, in)

	if built.Params.TokenEndPoint != "https://example.com/ocm/token" {
		t.Errorf("expected default token endpoint, got %q", built.Params.TokenEndPoint)
	}
}

func TestResolve_DerivesInviteAcceptDialogFromRouteInventory(t *testing.T) {
	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
		RouteOpts: service.RouteOpts{
			ExternalBasePath:    "/ocm",
			InviteAcceptEnabled: true,
		},
	}
	raw := map[string]any{"endpoint": "https://cloud.example.com/ocm"}

	built := resolve.Resolve(c, raw, in)

	if built.Params.InviteAcceptDialog != "https://cloud.example.com/ocm/ui/accept-invite" {
		t.Errorf("expected derived inviteAcceptDialog, got %q", built.Params.InviteAcceptDialog)
	}
}

func TestResolve_SkipsInviteAcceptDialogWithoutPublicOrigin(t *testing.T) {
	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: localidentity.Identity{ExternalBasePath: "/ocm"},
		RouteOpts: service.RouteOpts{
			ExternalBasePath:    "/ocm",
			InviteAcceptEnabled: true,
		},
	}

	built := resolve.Resolve(c, map[string]any{}, in)

	if built.Params.InviteAcceptDialog != "" {
		t.Errorf("expected empty inviteAcceptDialog without Origin, got %q", built.Params.InviteAcceptDialog)
	}
}
