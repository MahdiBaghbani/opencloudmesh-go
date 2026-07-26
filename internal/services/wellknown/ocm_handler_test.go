package wellknown

import (
	"sort"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
)

func TestNewOCMHandler_DisabledWhenNoEndpoint(t *testing.T) {
	c := &resolve.ProviderConfig{}

	h, err := newOCMHandler(c, nil, resolve.ResolveInputs{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.data.Enabled {
		t.Error("expected Enabled=false when endpoint is empty")
	}

	if h.data.APIVersion != "1.4.0" {
		t.Errorf("expected APIVersion '1.4.0', got %q", h.data.APIVersion)
	}

	if h.data.Provider != "OpenCloudMesh" {
		t.Errorf("expected Provider 'OpenCloudMesh', got %q", h.data.Provider)
	}
}

func TestNewOCMHandler_EnabledWithProjectedPaths(t *testing.T) {
	c := &resolve.ProviderConfig{
		WebDAVRoot: "/webdav/ocm/",
	}
	raw := map[string]any{"webdav_root": "/webdav/ocm/"}

	h, err := newOCMHandler(
		c,
		raw,
		handlerResolveInputs(t, "https://example.com", "/myapp"),
		testLogger(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !h.data.Enabled {
		t.Error("expected Enabled=true when paths are projected")
	}

	if h.data.EndPoint != "https://example.com/myapp/ocm" {
		t.Errorf("expected EndPoint 'https://example.com/myapp/ocm', got %q", h.data.EndPoint)
	}

	if len(h.data.ResourceTypes) != 2 {
		t.Fatalf("expected 2 resource types, got %d", len(h.data.ResourceTypes))
	}

	for i, wantName := range []string{"file", "folder"} {
		if h.data.ResourceTypes[i].Name != wantName {
			t.Errorf("resource type[%d] = %q, want %q", i, h.data.ResourceTypes[i].Name, wantName)
		}
	}

	rt := h.data.ResourceTypes[0]

	path, ok := rt.Protocols.StringRole("webdav")
	if !ok || path != "/webdav/ocm/" {
		t.Errorf("expected webdav protocol '/webdav/ocm/', got %q ok=%v", path, ok)
	}

	wr, ok := rt.Protocols.WebDAVReceive()
	if !ok || wr.URI != spec.WebDAVReceiveURIRelative {
		t.Fatalf("webdav-receive = %+v, ok=%v", wr, ok)
	}
}

func TestNewOCMHandler_WithKeyManager(t *testing.T) {
	c := &resolve.ProviderConfig{}

	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	in := handlerResolveInputs(t, "https://example.com", "")
	in.KeyManager = km

	h, err := newOCMHandler(c, nil, in, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false

	for _, cap := range h.data.Capabilities {
		if cap == "http-sig" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected 'http-sig' in capabilities when KeyManager is present")
	}

	if !h.data.HasCriteria(spec.CriteriaMustUseHTTPSig) {
		t.Error("expected must-use-http-sig in criteria when KeyManager is present")
	}
}

func TestNewOCMHandler_Criteria(t *testing.T) {
	t.Run("default criteria include token exchange", func(t *testing.T) {
		c := &resolve.ProviderConfig{}

		h, err := newOCMHandler(c, nil, handlerResolveInputs(t, "https://example.com", ""), testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.data.Criteria == nil {
			t.Error("expected Criteria to be non-nil")
		}

		if h.data.HasCriteria(spec.CriteriaMustUseHTTPSig) {
			t.Error("did not expect must-use-http-sig without http-sig capability")
		}

		if !h.data.HasCriteria(spec.CriteriaMustExchangeToken) {
			t.Error("expected must-exchange-token in default criteria")
		}
	})
}

func TestNewOCMHandler_InviteAcceptDialogFromRoutes(t *testing.T) {
	t.Run("derives inviteAcceptDialog when invite accept route active", func(t *testing.T) {
		c := &resolve.ProviderConfig{}
		resolveIn := resolve.ResolveInputs{
			LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
			RouteOpts: service.RouteOpts{
				ExternalBasePath:    "/ocm",
				InviteAcceptEnabled: true,
			},
			CodeFlow: policy.NewCodeFlow(),
		}

		h, err := newOCMHandler(c, map[string]any{}, resolveIn, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.data.InviteAcceptDialog != "https://cloud.example.com/ocm/ui/accept-invite" {
			t.Errorf("expected derived inviteAcceptDialog, got %q", h.data.InviteAcceptDialog)
		}
	})

	t.Run("explicit invite_accept_dialog overrides auto-derivation", func(t *testing.T) {
		c := &resolve.ProviderConfig{
			InviteAcceptDialog: "https://custom.example.com/accept",
		}
		resolveIn := resolve.ResolveInputs{
			LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
			RouteOpts: service.RouteOpts{
				ExternalBasePath:    "/ocm",
				InviteAcceptEnabled: true,
			},
			CodeFlow: policy.NewCodeFlow(),
		}

		raw := map[string]any{
			"invite_accept_dialog": "https://custom.example.com/accept",
		}

		h, err := newOCMHandler(c, raw, resolveIn, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.data.InviteAcceptDialog != "https://custom.example.com/accept" {
			t.Errorf("expected explicit inviteAcceptDialog preserved, got %q", h.data.InviteAcceptDialog)
		}
	})

	t.Run("no derivation when invite accept route inactive", func(t *testing.T) {
		c := &resolve.ProviderConfig{}
		resolveIn := resolve.ResolveInputs{
			LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
			RouteOpts:     service.RouteOpts{ExternalBasePath: "/ocm"},
			CodeFlow:      policy.NewCodeFlow(),
		}

		h, err := newOCMHandler(c, map[string]any{}, resolveIn, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.data.InviteAcceptDialog != "" {
			t.Errorf("expected empty inviteAcceptDialog when invite accept route inactive, got %q", h.data.InviteAcceptDialog)
		}
	})
}

func TestNewOCMHandler_InviteWAYFCapabilityFromRoute(t *testing.T) {
	t.Run("enabled when WAYF route active", func(t *testing.T) {
		c := &resolve.ProviderConfig{}
		in := resolve.ResolveInputs{
			LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
			RouteOpts: service.RouteOpts{
				ExternalBasePath:    "/ocm",
				WayfEnabled:         true,
				InviteAcceptEnabled: true,
			},
			CodeFlow: policy.NewCodeFlow(),
		}

		h, err := newOCMHandler(c, nil, in, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !h.data.HasCapability("invite-wayf") {
			t.Error("expected invite-wayf when WAYF route is enabled")
		}
	})

	t.Run("absent when WAYF route inactive", func(t *testing.T) {
		c := &resolve.ProviderConfig{}
		in := resolve.ResolveInputs{
			LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
			RouteOpts: service.RouteOpts{
				ExternalBasePath:    "/ocm",
				InviteAcceptEnabled: true,
			},
			CodeFlow: policy.NewCodeFlow(),
		}

		h, err := newOCMHandler(c, nil, in, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.data.HasCapability("invite-wayf") {
			t.Error("did not expect invite-wayf when WAYF route is inactive")
		}
	})
}

func TestNewOCMHandler_TruthfulCapabilitySet(t *testing.T) {
	c := &resolve.ProviderConfig{}
	in := handlerResolveInputs(t, "https://example.com", "")

	h, err := newOCMHandler(c, nil, in, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := append([]string(nil), h.data.Capabilities...)
	sort.Strings(got)

	want := []string{"exchange-token", "invites"}
	if len(got) != len(want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("capabilities = %v, want %v", got, want)
		}
	}
}
