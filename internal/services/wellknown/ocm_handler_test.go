package wellknown

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
)

func TestNewOCMHandler_DisabledWhenNoEndpoint(t *testing.T) {
	c := &OCMProviderConfig{}
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

func TestNewOCMHandler_EnabledWithEndpoint(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint:   "https://example.com/myapp",
		WebDAVRoot: "/webdav/ocm/",
	}
	h, err := newOCMHandler(c, nil, resolve.ResolveInputs{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !h.data.Enabled {
		t.Error("expected Enabled=true when endpoint is set")
	}
	if h.data.EndPoint != "https://example.com/myapp/ocm" {
		t.Errorf("expected EndPoint 'https://example.com/myapp/ocm', got %q", h.data.EndPoint)
	}

	// Check resource types
	if len(h.data.ResourceTypes) != 1 {
		t.Fatalf("expected 1 resource type, got %d", len(h.data.ResourceTypes))
	}
	rt := h.data.ResourceTypes[0]
	if rt.Name != "file" {
		t.Errorf("expected resource type 'file', got %q", rt.Name)
	}
	path, ok := rt.Protocols.StringRole("webdav")
	if !ok || path != "/webdav/ocm/" {
		t.Errorf("expected webdav protocol '/webdav/ocm/', got %q ok=%v", path, ok)
	}
}

func TestNewOCMHandler_WithKeyManager(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint: "https://example.com",
	}

	// Create a real KeyManager for testing
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	h, err := newOCMHandler(c, nil, resolve.ResolveInputs{KeyManager: km}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// http-sig capability should be present
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
}

func TestNewOCMHandler_Criteria(t *testing.T) {
	t.Run("empty by default", func(t *testing.T) {
		c := &OCMProviderConfig{
			Endpoint: "https://example.com",
		}
		h, err := newOCMHandler(c, nil, resolve.ResolveInputs{}, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.data.Criteria == nil {
			t.Error("expected Criteria to be non-nil (empty slice)")
		}
		if len(h.data.Criteria) != 0 {
			t.Errorf("expected empty criteria, got %v", h.data.Criteria)
		}
	})

	t.Run("with HTTP signatures", func(t *testing.T) {
		cfg := config.DevConfig()
		cfg.Signature.InboundMode = "strict"
		runtimePolicy := policy.NewRuntimePolicy(cfg, nil)
		c := &OCMProviderConfig{
			Endpoint: "https://example.com",
		}
		h, err := newOCMHandler(c, nil, resolve.ResolveInputs{RuntimePolicy: runtimePolicy}, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !h.data.HasCriteria(spec.CriteriaMustUseHTTPSig) {
			t.Error("expected must-use-http-sig in criteria")
		}
	})
}

func TestNewOCMHandler_RuntimePolicyDrivesHTTPSignatureCriteria(t *testing.T) {
	t.Run("derived from runtime policy when not explicitly configured", func(t *testing.T) {
		cfg := config.DevConfig()
		cfg.Signature.InboundMode = "strict"
		runtimePolicy := policy.NewRuntimePolicy(cfg, nil)
		c := &OCMProviderConfig{
			Endpoint: "https://example.com",
		}
		h, err := newOCMHandler(c, map[string]any{}, resolve.ResolveInputs{RuntimePolicy: runtimePolicy}, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !h.data.HasCriteria(spec.CriteriaMustUseHTTPSig) {
			t.Error("expected must-use-http-sig criteria from runtime policy")
		}
	})

	t.Run("lenient runtime posture omits criterion when not explicitly configured", func(t *testing.T) {
		cfg := config.DevConfig()
		cfg.Signature.InboundMode = "lenient"
		runtimePolicy := policy.NewRuntimePolicy(cfg, nil)
		c := &OCMProviderConfig{
			Endpoint: "https://example.com",
		}
		h, err := newOCMHandler(c, map[string]any{}, resolve.ResolveInputs{RuntimePolicy: runtimePolicy}, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.data.HasCriteria(spec.CriteriaMustUseHTTPSig) {
			t.Error("did not expect must-use-http-sig for lenient runtime posture")
		}
	})

	t.Run("off runtime posture omits criterion when not explicitly configured", func(t *testing.T) {
		cfg := config.DevConfig()
		cfg.Signature.InboundMode = "off"
		runtimePolicy := policy.NewRuntimePolicy(cfg, nil)
		c := &OCMProviderConfig{
			Endpoint: "https://example.com",
		}
		h, err := newOCMHandler(c, map[string]any{}, resolve.ResolveInputs{RuntimePolicy: runtimePolicy}, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.data.HasCriteria(spec.CriteriaMustUseHTTPSig) {
			t.Error("did not expect must-use-http-sig for off runtime posture")
		}
	})

	t.Run("removed service-local key does not override runtime policy", func(t *testing.T) {
		cfg := config.DevConfig()
		cfg.Signature.InboundMode = "strict"
		runtimePolicy := policy.NewRuntimePolicy(cfg, nil)
		c := &OCMProviderConfig{
			Endpoint: "https://example.com",
		}
		raw := map[string]any{
			"advertise_http_request_signatures": false,
		}

		h, err := newOCMHandler(c, raw, resolve.ResolveInputs{RuntimePolicy: runtimePolicy}, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !h.data.HasCriteria(spec.CriteriaMustUseHTTPSig) {
			t.Error("expected must-use-http-sig to follow runtime policy")
		}
	})
}

func TestNewOCMHandler_RuntimePolicyDrivesAPIVersionOverrides(t *testing.T) {
	// Scoped presets do not grant a global Nextcloud crawler apiVersion override.
	// Per-peer overrides route through the peercompat gate.
	t.Run("scoped compat preset grants no global crawler override", func(t *testing.T) {
		cfg := config.CompatConfig()
		runtimePolicy := policy.NewRuntimePolicy(cfg, nil)
		c := &OCMProviderConfig{
			Endpoint: "https://example.com",
		}
		h, err := newOCMHandler(c, map[string]any{}, resolve.ResolveInputs{RuntimePolicy: runtimePolicy}, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(h.overrides) != 0 {
			t.Fatalf("expected no crawler overrides, got %d", len(h.overrides))
		}

		req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
		req.Header.Set("User-Agent", "Nextcloud Server Crawler")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		var disc spec.Discovery
		if err := json.Unmarshal(rr.Body.Bytes(), &disc); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if disc.APIVersion != "1.4.0" {
			t.Fatalf("expected default apiVersion 1.4.0 with no crawler override, got %q", disc.APIVersion)
		}
	})

	t.Run("strict runtime posture suppresses crawler override even on dev preset", func(t *testing.T) {
		cfg := config.DevConfig()
		cfg.RequireTokenExchange = true
		cfg.PeerPolicy = "strict"
		cfg.Signature.InboundMode = "strict"
		cfg.Signature.OutboundMode = "strict"
		cfg.Signature.PeerProfileLevelOverride = "off"
		cfg.Signature.AllowMismatch = false
		cfg.CompatibilityScope = "none"
		cfg.TLS.Mode = "selfsigned"
		cfg.OutboundHTTP.DerivedSSRFMode = "strict"
		cfg.OutboundHTTP.InsecureSkipVerify = false
		runtimePolicy := policy.NewRuntimePolicy(cfg, nil)
		c := &OCMProviderConfig{
			Endpoint: "https://example.com",
		}
		h, err := newOCMHandler(c, map[string]any{}, resolve.ResolveInputs{RuntimePolicy: runtimePolicy}, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(h.overrides) != 0 {
			t.Fatalf("expected no crawler overrides for strict runtime posture, got %d", len(h.overrides))
		}

		req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
		req.Header.Set("User-Agent", "Nextcloud Server Crawler")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		var disc spec.Discovery
		if err := json.Unmarshal(rr.Body.Bytes(), &disc); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if disc.APIVersion != "1.4.0" {
			t.Fatalf("expected default apiVersion 1.4.0, got %q", disc.APIVersion)
		}
	})
}

func TestNewOCMHandler_InvalidEndpointURL(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint: "://invalid-url",
	}
	h, err := newOCMHandler(c, nil, resolve.ResolveInputs{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should gracefully return disabled discovery
	if h.data.Enabled {
		t.Error("expected Enabled=false for invalid URL")
	}
}

func TestNewOCMHandler_InviteAcceptDialogFromRoutes(t *testing.T) {
	t.Run("derives inviteAcceptDialog when invite accept route active", func(t *testing.T) {
		c := &OCMProviderConfig{
			Endpoint: "https://cloud.example.com/ocm",
		}
		resolveIn := resolve.ResolveInputs{
			LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
			RouteOpts: service.RouteOpts{
				ExternalBasePath:    "/ocm",
				InviteAcceptEnabled: true,
			},
		}

		// rawOCMProvider does NOT contain invite_accept_dialog
		raw := map[string]any{
			"endpoint": "https://cloud.example.com/ocm",
		}

		h, err := newOCMHandler(c, raw, resolveIn, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.data.InviteAcceptDialog != "https://cloud.example.com/ocm/ui/accept-invite" {
			t.Errorf("expected derived inviteAcceptDialog, got %q", h.data.InviteAcceptDialog)
		}
	})

	t.Run("explicit invite_accept_dialog overrides auto-derivation", func(t *testing.T) {
		c := &OCMProviderConfig{
			Endpoint:           "https://cloud.example.com/ocm",
			InviteAcceptDialog: "https://custom.example.com/accept",
		}
		resolveIn := resolve.ResolveInputs{
			LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
			RouteOpts: service.RouteOpts{
				ExternalBasePath:    "/ocm",
				InviteAcceptEnabled: true,
			},
		}

		// rawOCMProvider DOES contain invite_accept_dialog
		raw := map[string]any{
			"endpoint":             "https://cloud.example.com/ocm",
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
		c := &OCMProviderConfig{
			Endpoint: "https://cloud.example.com/ocm",
		}
		resolveIn := resolve.ResolveInputs{
			LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
			RouteOpts:     service.RouteOpts{ExternalBasePath: "/ocm"},
		}

		raw := map[string]any{
			"endpoint": "https://cloud.example.com/ocm",
		}

		h, err := newOCMHandler(c, raw, resolveIn, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.data.InviteAcceptDialog != "" {
			t.Errorf("expected empty inviteAcceptDialog when invite accept route inactive, got %q", h.data.InviteAcceptDialog)
		}
	})
}

func TestNewOCMHandler_InviteWAYFCapability(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint:            "https://cloud.example.com/ocm",
		InviteAcceptDialog:  "https://cloud.example.com/ocm/ui/accept-invite",
		AdvertiseInviteWAYF: true,
	}
	h, err := newOCMHandler(c, nil, resolve.ResolveInputs{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, cap := range h.data.Capabilities {
		if cap == "invite-wayf" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'invite-wayf' in capabilities when AdvertiseInviteWAYF=true")
	}
}

func TestNewOCMHandler_UnconditionalCapabilities(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint: "https://example.com",
	}
	h, err := newOCMHandler(c, nil, resolve.ResolveInputs{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	required := []string{"invites", "protocol-object", "notifications"}
	capSet := make(map[string]bool)
	for _, cap := range h.data.Capabilities {
		capSet[cap] = true
	}
	for _, req := range required {
		if !capSet[req] {
			t.Errorf("expected unconditional capability %q in capabilities %v", req, h.data.Capabilities)
		}
	}
}
