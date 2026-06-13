package resolve_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"
)

func TestResolve_AppliesServiceLocalDefaults(t *testing.T) {
	c := &resolve.ProviderConfig{}
	in := resolve.Resolve(c, nil, resolve.ResolveInputs{})

	if in.Params.OCMPrefix != "ocm" {
		t.Errorf("expected OCMPrefix default 'ocm', got %q", in.Params.OCMPrefix)
	}
	if in.Params.Provider != "OpenCloudMesh" {
		t.Errorf("expected Provider default 'OpenCloudMesh', got %q", in.Params.Provider)
	}
}

func TestResolve_DerivesEndpointAndWebDAVRoot(t *testing.T) {
	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
	}

	built := resolve.Resolve(c, map[string]any{}, in)

	if built.Params.Endpoint != "https://cloud.example.com/ocm" {
		t.Errorf("expected derived endpoint, got %q", built.Params.Endpoint)
	}
	if built.Params.WebDAVRoot != "/ocm/webdav/ocm/" {
		t.Errorf("expected derived webdav_root, got %q", built.Params.WebDAVRoot)
	}
}

func TestResolve_SkipsEndpointDerivationWithoutPublicOrigin(t *testing.T) {
	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{LocalIdentity: localidentity.Identity{ExternalBasePath: "/ocm"}}

	built := resolve.Resolve(c, map[string]any{}, in)

	if built.Params.Endpoint != "" {
		t.Errorf("expected empty endpoint without Origin, got %q", built.Params.Endpoint)
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
	}
	raw := map[string]any{
		"endpoint":    "https://explicit.example.com",
		"webdav_root": "/explicit/dav/",
	}

	built := resolve.Resolve(c, raw, in)

	if built.Params.Endpoint != "https://explicit.example.com" {
		t.Errorf("expected explicit endpoint preserved, got %q", built.Params.Endpoint)
	}
	if built.Params.WebDAVRoot != "/explicit/dav/" {
		t.Errorf("expected explicit webdav_root preserved, got %q", built.Params.WebDAVRoot)
	}
}

func TestResolve_TokenExchangePathDefault(t *testing.T) {
	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{LocalIdentity: tslocalid.MustTestIdentity(t, "https://example.com", "")}

	built := resolve.Resolve(c, nil, in)

	if built.Params.TokenExchangePath != "token" {
		t.Errorf("expected default token path 'token', got %q", built.Params.TokenExchangePath)
	}
}

func TestResolve_DerivesCompatibilityOverride(t *testing.T) {
	cfg := config.CompatConfig()
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://example.com", ""),
		RuntimePolicy: policy.NewRuntimePolicy(cfg, nil),
	}
	c := &resolve.ProviderConfig{Endpoint: "https://example.com"}

	built := resolve.Resolve(c, map[string]any{}, in)

	if len(built.Overrides) != 1 {
		t.Fatalf("expected one crawler override, got %d", len(built.Overrides))
	}
	if built.Overrides[0].UserAgentContains != "Nextcloud Server Crawler" || built.Overrides[0].APIVersion != "1.1" {
		t.Errorf("unexpected override: %+v", built.Overrides[0])
	}
}

func TestResolve_DerivesInviteAcceptDialogFromWAYF(t *testing.T) {
	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
		UIWayfEnabled: true,
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
		UIWayfEnabled: true,
	}

	built := resolve.Resolve(c, map[string]any{}, in)

	if built.Params.InviteAcceptDialog != "" {
		t.Errorf("expected empty inviteAcceptDialog without Origin, got %q", built.Params.InviteAcceptDialog)
	}
}

func TestUIWayfEnabledFromConfig(t *testing.T) {
	tests := []struct {
		name  string
		uiRaw map[string]any
		want  bool
	}{
		{"nil config", nil, false},
		{"empty config", map[string]any{}, false},
		{"wayf disabled", map[string]any{"wayf": map[string]any{"enabled": false}}, false},
		{"wayf enabled", map[string]any{"wayf": map[string]any{"enabled": true}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolve.UIWayfEnabledFromConfig(tt.uiRaw)
			if got != tt.want {
				t.Errorf("UIWayfEnabledFromConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
