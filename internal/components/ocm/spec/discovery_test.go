package spec_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
)

func TestHasCriteria_IETFAndLegacyAliases(t *testing.T) {
	disc := &spec.Discovery{
		Criteria: []string{spec.CriteriaMustUseHTTPSig, spec.CriteriaMustExchangeToken},
	}

	for _, query := range []string{
		spec.CriteriaMustUseHTTPSig,
		"http-request-signatures",
		spec.CriteriaMustExchangeToken,
		"token-exchange",
	} {
		if !disc.HasCriteria(query) {
			t.Errorf("HasCriteria(%q) = false, want true", query)
		}
	}
	if disc.HasCriteria("unknown") {
		t.Error("HasCriteria(unknown) should be false")
	}
}

func TestDeriveDiscoveryPaths_RootMount(t *testing.T) {
	id := tslocalid.MustTestIdentity(t, "https://example.com", "")
	paths, ok := spec.DeriveDiscoveryPaths(id, service.DefaultRouteOpts())
	if !ok {
		t.Fatal("expected projection ok")
	}
	if paths.EndPoint != "https://example.com/ocm" {
		t.Errorf("EndPoint = %q, want https://example.com/ocm", paths.EndPoint)
	}
	if paths.TokenEndPoint != "https://example.com/ocm/token" {
		t.Errorf("TokenEndPoint = %q, want https://example.com/ocm/token", paths.TokenEndPoint)
	}
	if paths.WebDAVRoot != "/webdav/ocm/" {
		t.Errorf("WebDAVRoot = %q, want /webdav/ocm/", paths.WebDAVRoot)
	}
	if paths.InviteAcceptDialog != "" {
		t.Errorf("InviteAcceptDialog = %q, want empty when invite accept disabled", paths.InviteAcceptDialog)
	}
}

func TestDeriveDiscoveryPaths_BasePathAndInviteAccept(t *testing.T) {
	id := tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm")
	opts := service.RouteOpts{
		ExternalBasePath:    "/ocm",
		WayfEnabled:         true,
		InviteAcceptEnabled: true,
		TokenExchangePath:   "token",
	}
	paths, ok := spec.DeriveDiscoveryPaths(id, opts)
	if !ok {
		t.Fatal("expected projection ok")
	}
	if paths.EndPoint != "https://cloud.example.com/ocm/ocm" {
		t.Errorf("EndPoint = %q, want https://cloud.example.com/ocm/ocm", paths.EndPoint)
	}
	if paths.WebDAVRoot != "/ocm/webdav/ocm/" {
		t.Errorf("WebDAVRoot = %q, want /ocm/webdav/ocm/", paths.WebDAVRoot)
	}
	if paths.InviteAcceptDialog != "https://cloud.example.com/ocm/ui/accept-invite" {
		t.Errorf("InviteAcceptDialog = %q", paths.InviteAcceptDialog)
	}
}

func TestResolveInviteAcceptDialog_RelativePeerValue(t *testing.T) {
	got := spec.ResolveInviteAcceptDialog("https://peer.example.com/ocm", "/apps/ocm/invite-accept")
	want := "https://peer.example.com/apps/ocm/invite-accept"
	if got != want {
		t.Errorf("ResolveInviteAcceptDialog() = %q, want %q", got, want)
	}
}

func TestDeriveDiscoveryPathsFromEndpointBase_ExplicitEndpoint(t *testing.T) {
	opts := service.RouteOpts{
		ExternalBasePath:    "/ocm",
		InviteAcceptEnabled: true,
		TokenExchangePath:   "token",
	}
	paths := spec.DeriveDiscoveryPathsFromEndpointBase("https://cloud.example.com/ocm", "ocm", opts)

	if paths.EndPoint != "https://cloud.example.com/ocm/ocm" {
		t.Errorf("EndPoint = %q", paths.EndPoint)
	}
	if paths.TokenEndPoint != "https://cloud.example.com/ocm/ocm/token" {
		t.Errorf("TokenEndPoint = %q", paths.TokenEndPoint)
	}
	if paths.WebDAVRoot != "" {
		t.Errorf("WebDAVRoot = %q, want empty (not projected from explicit endpoint base)", paths.WebDAVRoot)
	}
	if paths.InviteAcceptDialog != "" {
		t.Errorf("InviteAcceptDialog = %q, want empty (not projected from explicit endpoint base)", paths.InviteAcceptDialog)
	}
}

func TestDeriveDiscoveryPaths_RequiresOrigin(t *testing.T) {
	_, ok := spec.DeriveDiscoveryPaths(localidentity.Identity{ExternalBasePath: "/ocm"}, service.DefaultRouteOpts())
	if ok {
		t.Error("expected projection false without Origin")
	}
}
