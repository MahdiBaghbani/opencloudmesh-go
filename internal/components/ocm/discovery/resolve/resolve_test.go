package resolve

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestResolve_AppliesServiceLocalDefaults(t *testing.T) {
	c := &ProviderConfig{}
	in := Resolve(c, nil, ResolveInputs{})

	if in.Params.OCMPrefix != "ocm" {
		t.Errorf("expected OCMPrefix default 'ocm', got %q", in.Params.OCMPrefix)
	}
	if in.Params.Provider != "OpenCloudMesh" {
		t.Errorf("expected Provider default 'OpenCloudMesh', got %q", in.Params.Provider)
	}
}

func TestResolve_DerivesEndpointAndWebDAVRoot(t *testing.T) {
	c := &ProviderConfig{}
	in := ResolveInputs{
		PublicOrigin:     "https://cloud.example.com",
		ExternalBasePath: "/ocm",
	}

	built := Resolve(c, map[string]any{}, in)

	if built.Params.Endpoint != "https://cloud.example.com/ocm" {
		t.Errorf("expected derived endpoint, got %q", built.Params.Endpoint)
	}
	if built.Params.WebDAVRoot != "/ocm/webdav/ocm/" {
		t.Errorf("expected derived webdav_root, got %q", built.Params.WebDAVRoot)
	}
}

func TestResolve_SkipsEndpointDerivationWithoutPublicOrigin(t *testing.T) {
	c := &ProviderConfig{}
	in := ResolveInputs{ExternalBasePath: "/ocm"}

	built := Resolve(c, map[string]any{}, in)

	if built.Params.Endpoint != "" {
		t.Errorf("expected empty endpoint without PublicOrigin, got %q", built.Params.Endpoint)
	}
	if built.Params.WebDAVRoot != "/ocm/webdav/ocm/" {
		t.Errorf("expected derived webdav_root, got %q", built.Params.WebDAVRoot)
	}
}

func TestResolve_RawConfigWinsOverDerivation(t *testing.T) {
	c := &ProviderConfig{
		Endpoint:   "https://explicit.example.com",
		WebDAVRoot: "/explicit/dav/",
	}
	in := ResolveInputs{
		PublicOrigin:     "https://cloud.example.com",
		ExternalBasePath: "/ocm",
	}
	raw := map[string]any{
		"endpoint":    "https://explicit.example.com",
		"webdav_root": "/explicit/dav/",
	}

	built := Resolve(c, raw, in)

	if built.Params.Endpoint != "https://explicit.example.com" {
		t.Errorf("expected explicit endpoint preserved, got %q", built.Params.Endpoint)
	}
	if built.Params.WebDAVRoot != "/explicit/dav/" {
		t.Errorf("expected explicit webdav_root preserved, got %q", built.Params.WebDAVRoot)
	}
}

func TestResolve_TokenExchangePathDefault(t *testing.T) {
	c := &ProviderConfig{}
	in := ResolveInputs{PublicOrigin: "https://example.com"}

	built := Resolve(c, nil, in)

	if built.Params.TokenExchangePath != "token" {
		t.Errorf("expected default token path 'token', got %q", built.Params.TokenExchangePath)
	}
}

func TestResolve_DerivesCompatibilityOverride(t *testing.T) {
	cfg := config.CompatConfig()
	in := ResolveInputs{
		PublicOrigin:  "https://example.com",
		RuntimePolicy: policy.NewRuntimePolicy(cfg, nil),
	}
	c := &ProviderConfig{Endpoint: "https://example.com"}

	built := Resolve(c, map[string]any{}, in)

	if len(built.Overrides) != 1 {
		t.Fatalf("expected one crawler override, got %d", len(built.Overrides))
	}
	if built.Overrides[0].UserAgentContains != "Nextcloud Server Crawler" || built.Overrides[0].APIVersion != "1.1" {
		t.Errorf("unexpected override: %+v", built.Overrides[0])
	}
}

func TestResolve_DerivesInviteAcceptDialogFromWAYF(t *testing.T) {
	c := &ProviderConfig{}
	in := ResolveInputs{
		PublicOrigin:     "https://cloud.example.com",
		ExternalBasePath: "/ocm",
		UIWayfEnabled:    true,
	}
	raw := map[string]any{"endpoint": "https://cloud.example.com/ocm"}

	built := Resolve(c, raw, in)

	if built.Params.InviteAcceptDialog != "https://cloud.example.com/ocm/ui/accept-invite" {
		t.Errorf("expected derived inviteAcceptDialog, got %q", built.Params.InviteAcceptDialog)
	}
}

func TestResolve_SkipsInviteAcceptDialogWithoutPublicOrigin(t *testing.T) {
	c := &ProviderConfig{}
	in := ResolveInputs{
		ExternalBasePath: "/ocm",
		UIWayfEnabled:    true,
	}

	built := Resolve(c, map[string]any{}, in)

	if built.Params.InviteAcceptDialog != "" {
		t.Errorf("expected empty inviteAcceptDialog without PublicOrigin, got %q", built.Params.InviteAcceptDialog)
	}
}

func TestUIWayfEnabledFromConfig(t *testing.T) {
	tests := []struct {
		name  string
		uiRaw map[string]any
		want  bool
	}{
		{
			name:  "nil ui config",
			uiRaw: nil,
			want:  false,
		},
		{
			name: "disabled nested map",
			uiRaw: map[string]any{
				"wayf": map[string]any{
					"enabled": false,
				},
			},
			want: false,
		},
		{
			name: "enabled nested map",
			uiRaw: map[string]any{
				"wayf": map[string]any{
					"enabled": true,
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UIWayfEnabledFromConfig(tt.uiRaw); got != tt.want {
				t.Errorf("UIWayfEnabledFromConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
