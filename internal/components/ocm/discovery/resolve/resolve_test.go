package resolve

import (
	"log/slog"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestResolve_AppliesServiceLocalDefaults(t *testing.T) {
	c := &ProviderConfig{}
	in := Resolve(c, nil, &deps.Deps{}, testLogger())

	if in.Params.OCMPrefix != "ocm" {
		t.Errorf("expected OCMPrefix default 'ocm', got %q", in.Params.OCMPrefix)
	}
	if in.Params.Provider != "OpenCloudMesh" {
		t.Errorf("expected Provider default 'OpenCloudMesh', got %q", in.Params.Provider)
	}
}

func TestResolve_DerivesEndpointAndWebDAVRoot(t *testing.T) {
	c := &ProviderConfig{}
	d := &deps.Deps{
		Config: &config.Config{
			PublicOrigin:     "https://cloud.example.com",
			ExternalBasePath: "/ocm",
		},
	}

	// Raw map omits endpoint and webdav_root, so both are derived.
	in := Resolve(c, map[string]any{}, d, testLogger())

	if in.Params.Endpoint != "https://cloud.example.com/ocm" {
		t.Errorf("expected derived endpoint, got %q", in.Params.Endpoint)
	}
	if in.Params.WebDAVRoot != "/ocm/webdav/ocm/" {
		t.Errorf("expected derived webdav_root, got %q", in.Params.WebDAVRoot)
	}
}

func TestResolve_RawConfigWinsOverDerivation(t *testing.T) {
	c := &ProviderConfig{
		Endpoint:   "https://explicit.example.com",
		WebDAVRoot: "/explicit/dav/",
	}
	d := &deps.Deps{
		Config: &config.Config{
			PublicOrigin:     "https://cloud.example.com",
			ExternalBasePath: "/ocm",
		},
	}
	raw := map[string]any{
		"endpoint":    "https://explicit.example.com",
		"webdav_root": "/explicit/dav/",
	}

	in := Resolve(c, raw, d, testLogger())

	if in.Params.Endpoint != "https://explicit.example.com" {
		t.Errorf("expected explicit endpoint preserved, got %q", in.Params.Endpoint)
	}
	if in.Params.WebDAVRoot != "/explicit/dav/" {
		t.Errorf("expected explicit webdav_root preserved, got %q", in.Params.WebDAVRoot)
	}
}

func TestResolve_TokenExchangePathDefault(t *testing.T) {
	c := &ProviderConfig{}
	d := &deps.Deps{Config: &config.Config{PublicOrigin: "https://example.com"}}

	in := Resolve(c, nil, d, testLogger())

	if in.Params.TokenExchangePath != "token" {
		t.Errorf("expected default token path 'token', got %q", in.Params.TokenExchangePath)
	}
}

func TestResolve_DerivesCompatibilityOverride(t *testing.T) {
	cfg := config.CompatConfig()
	d := &deps.Deps{
		Config:        cfg,
		RuntimePolicy: policy.NewRuntimePolicy(cfg, nil),
	}
	c := &ProviderConfig{Endpoint: "https://example.com"}

	in := Resolve(c, map[string]any{}, d, testLogger())

	if len(in.Overrides) != 1 {
		t.Fatalf("expected one crawler override, got %d", len(in.Overrides))
	}
	if in.Overrides[0].UserAgentContains != "Nextcloud Server Crawler" || in.Overrides[0].APIVersion != "1.1" {
		t.Errorf("unexpected override: %+v", in.Overrides[0])
	}
}

func TestResolve_DerivesInviteAcceptDialogFromWAYF(t *testing.T) {
	c := &ProviderConfig{}
	d := &deps.Deps{
		Config: &config.Config{
			PublicOrigin:     "https://cloud.example.com",
			ExternalBasePath: "/ocm",
			HTTP: config.HTTPConfig{
				Services: map[string]map[string]any{
					"ui": {"wayf": map[string]any{"enabled": true}},
				},
			},
		},
	}
	raw := map[string]any{"endpoint": "https://cloud.example.com/ocm"}

	in := Resolve(c, raw, d, testLogger())

	if in.Params.InviteAcceptDialog != "https://cloud.example.com/ocm/ui/accept-invite" {
		t.Errorf("expected derived inviteAcceptDialog, got %q", in.Params.InviteAcceptDialog)
	}
}
