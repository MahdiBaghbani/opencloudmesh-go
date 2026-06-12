package wellknown

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
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
	if h.data.APIVersion != "1.2.2" {
		t.Errorf("expected APIVersion '1.2.2', got %q", h.data.APIVersion)
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
	if rt.Protocols["webdav"] != "/webdav/ocm/" {
		t.Errorf("expected webdav protocol '/webdav/ocm/', got %q", rt.Protocols["webdav"])
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

	// Public keys should be populated
	if len(h.data.PublicKeys) != 1 {
		t.Fatalf("expected 1 public key, got %d", len(h.data.PublicKeys))
	}

	pk := h.data.PublicKeys[0]
	if pk.Algorithm != "ed25519" {
		t.Errorf("expected algorithm 'ed25519', got %q", pk.Algorithm)
	}
	if pk.KeyID != km.GetKeyID() {
		t.Errorf("expected keyID %q, got %q", km.GetKeyID(), pk.KeyID)
	}
	if pk.PublicKeyPem == "" {
		t.Error("expected non-empty PublicKeyPem")
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

		found := false
		for _, crit := range h.data.Criteria {
			if crit == "http-request-signatures" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected 'http-request-signatures' in criteria")
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

		found := false
		for _, crit := range h.data.Criteria {
			if crit == "http-request-signatures" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected http-request-signatures criteria from runtime policy")
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

		for _, crit := range h.data.Criteria {
			if crit == "http-request-signatures" {
				t.Error("did not expect http-request-signatures for lenient runtime posture")
			}
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

		for _, crit := range h.data.Criteria {
			if crit == "http-request-signatures" {
				t.Error("did not expect http-request-signatures for off runtime posture")
			}
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

		for _, crit := range h.data.Criteria {
			if crit == "http-request-signatures" {
				return
			}
		}
		t.Error("expected http-request-signatures to follow runtime policy")
	})
}

func TestNewOCMHandler_RuntimePolicyDrivesAPIVersionOverrides(t *testing.T) {
	t.Run("unbounded compatibility adds crawler override", func(t *testing.T) {
		cfg := config.CompatConfig()
		runtimePolicy := policy.NewRuntimePolicy(cfg, nil)
		c := &OCMProviderConfig{
			Endpoint: "https://example.com",
		}
		h, err := newOCMHandler(c, map[string]any{}, resolve.ResolveInputs{RuntimePolicy: runtimePolicy}, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(h.overrides) != 1 {
			t.Fatalf("expected one crawler override, got %d", len(h.overrides))
		}

		req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
		req.Header.Set("User-Agent", "Nextcloud Server Crawler")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		var disc spec.Discovery
		if err := json.Unmarshal(rr.Body.Bytes(), &disc); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if disc.APIVersion != "1.1" {
			t.Fatalf("expected apiVersion 1.1 for crawler override, got %q", disc.APIVersion)
		}
	})

	t.Run("strict runtime posture suppresses crawler override even on dev preset", func(t *testing.T) {
		cfg := config.DevConfig()
		cfg.RequireTokenExchange = true
		cfg.PeerPolicy = "strict"
		cfg.Signature.InboundMode = "strict"
		cfg.Signature.OutboundMode = "strict"
		cfg.Signature.PeerProfileLevelOverride = "off"
		cfg.Signature.OnDiscoveryError = "reject"
		cfg.Signature.AllowMismatch = false
		cfg.CompatibilityScope = "none"
		cfg.TLS.Mode = "selfsigned"
		cfg.OutboundHTTP.SSRFMode = "strict"
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
		if disc.APIVersion != "1.2.2" {
			t.Fatalf("expected default apiVersion 1.2.2, got %q", disc.APIVersion)
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

func TestNewOCMHandler_WAYFAutoDerivation(t *testing.T) {
	t.Run("derives inviteAcceptDialog when WAYF enabled", func(t *testing.T) {
		c := &OCMProviderConfig{
			Endpoint: "https://cloud.example.com/ocm",
		}
		resolveIn := resolve.ResolveInputs{
			PublicOrigin:     "https://cloud.example.com",
			ExternalBasePath: "/ocm",
			UIWayfEnabled:    true,
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
			PublicOrigin:     "https://cloud.example.com",
			ExternalBasePath: "/ocm",
			UIWayfEnabled:    true,
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

	t.Run("no derivation when WAYF disabled", func(t *testing.T) {
		c := &OCMProviderConfig{
			Endpoint: "https://cloud.example.com/ocm",
		}
		resolveIn := resolve.ResolveInputs{
			PublicOrigin:     "https://cloud.example.com",
			ExternalBasePath: "/ocm",
			UIWayfEnabled:    false,
		}

		raw := map[string]any{
			"endpoint": "https://cloud.example.com/ocm",
		}

		h, err := newOCMHandler(c, raw, resolveIn, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.data.InviteAcceptDialog != "" {
			t.Errorf("expected empty inviteAcceptDialog when WAYF disabled, got %q", h.data.InviteAcceptDialog)
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
		t.Error("expected 'invite-wayf' in capabilities when AdvertiseInviteWAYF=true and InviteAcceptDialog is set")
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

	required := []string{"invites", "webdav-uri", "protocol-object", "notifications"}
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
