package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestOCMProviderConfig_ApplyDefaults(t *testing.T) {
	c := &OCMProviderConfig{}
	c.ApplyDefaults()

	if c.OCMPrefix != "ocm" {
		t.Errorf("expected OCMPrefix 'ocm', got %q", c.OCMPrefix)
	}
	if c.Provider != "OpenCloudMesh" {
		t.Errorf("expected Provider 'OpenCloudMesh', got %q", c.Provider)
	}
	if c.WebDAVRoot != "/webdav/ocm/" {
		t.Errorf("expected WebDAVRoot '/webdav/ocm/', got %q", c.WebDAVRoot)
	}
	if c.TokenExchange.Path != "token" {
		t.Errorf("expected TokenExchange.Path 'token', got %q", c.TokenExchange.Path)
	}
}

func TestOCMProviderConfig_ApplyDefaults_PreservesCustomValues(t *testing.T) {
	c := &OCMProviderConfig{
		OCMPrefix:  "custom-ocm",
		Provider:   "CustomProvider",
		WebDAVRoot: "/custom/webdav/",
	}
	c.TokenExchange.Path = "custom-token"
	c.ApplyDefaults()

	if c.OCMPrefix != "custom-ocm" {
		t.Errorf("expected OCMPrefix 'custom-ocm', got %q", c.OCMPrefix)
	}
	if c.Provider != "CustomProvider" {
		t.Errorf("expected Provider 'CustomProvider', got %q", c.Provider)
	}
	if c.WebDAVRoot != "/custom/webdav/" {
		t.Errorf("expected WebDAVRoot '/custom/webdav/', got %q", c.WebDAVRoot)
	}
	if c.TokenExchange.Path != "custom-token" {
		t.Errorf("expected TokenExchange.Path 'custom-token', got %q", c.TokenExchange.Path)
	}
}

func TestNewOCMHandler_DisabledWhenNoEndpoint(t *testing.T) {
	c := &OCMProviderConfig{}
	deps := &deps.Deps{}

	h, err := newOCMHandler(c, deps, testLogger())
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
		Endpoint: "https://example.com/myapp",
	}
	deps := &deps.Deps{}

	h, err := newOCMHandler(c, deps, testLogger())
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

func TestNewOCMHandler_TokenExchangeDisabled(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint: "https://example.com",
	}
	c.TokenExchange.Enabled = false
	deps := &deps.Deps{}

	h, err := newOCMHandler(c, deps, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Token exchange should NOT be in capabilities
	for _, cap := range h.data.Capabilities {
		if cap == "exchange-token" {
			t.Error("expected 'exchange-token' to NOT be in capabilities when disabled")
		}
	}

	// tokenEndPoint should be empty
	if h.data.TokenEndPoint != "" {
		t.Errorf("expected empty tokenEndPoint, got %q", h.data.TokenEndPoint)
	}
}

func TestNewOCMHandler_TokenExchangeEnabled(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint: "https://example.com/app",
	}
	c.TokenExchange.Enabled = true
	c.TokenExchange.Path = "exchange"
	deps := &deps.Deps{}

	h, err := newOCMHandler(c, deps, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Token exchange should be in capabilities
	found := false
	for _, cap := range h.data.Capabilities {
		if cap == "exchange-token" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'exchange-token' in capabilities")
	}

	// tokenEndPoint should be set
	expected := "https://example.com/app/ocm/exchange"
	if h.data.TokenEndPoint != expected {
		t.Errorf("expected tokenEndPoint %q, got %q", expected, h.data.TokenEndPoint)
	}
}

func TestNewOCMHandler_TokenExchangeDefaultPath(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint: "https://example.com",
	}
	c.TokenExchange.Enabled = true
	// Path is empty, should default to "token"
	deps := &deps.Deps{}

	h, err := newOCMHandler(c, deps, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "https://example.com/ocm/token"
	if h.data.TokenEndPoint != expected {
		t.Errorf("expected tokenEndPoint %q, got %q", expected, h.data.TokenEndPoint)
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

	d := &deps.Deps{
		KeyManager: km,
	}

	h, err := newOCMHandler(c, d, testLogger())
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
		deps := &deps.Deps{}

		h, err := newOCMHandler(c, deps, testLogger())
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
		c := &OCMProviderConfig{
			Endpoint:                       "https://example.com",
			AdvertiseHTTPRequestSignatures: true,
		}
		deps := &deps.Deps{}

		h, err := newOCMHandler(c, deps, testLogger())
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

func TestNewOCMHandler_InvalidEndpointURL(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint: "://invalid-url",
	}
	deps := &deps.Deps{}

	h, err := newOCMHandler(c, deps, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should gracefully return disabled discovery
	if h.data.Enabled {
		t.Error("expected Enabled=false for invalid URL")
	}
}

func TestOCMHandler_ServeHTTP(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint: "https://example.com",
		Provider: "TestProvider",
	}
	c.TokenExchange.Enabled = true
	deps := &deps.Deps{}

	h, err := newOCMHandler(c, deps, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}

	var disc spec.Discovery
	if err := json.NewDecoder(w.Body).Decode(&disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !disc.Enabled {
		t.Error("expected Enabled=true in response")
	}
	if disc.Provider != "TestProvider" {
		t.Errorf("expected Provider 'TestProvider', got %q", disc.Provider)
	}
	if disc.TokenEndPoint == "" {
		t.Error("expected non-empty tokenEndPoint")
	}
}

func TestOCMHandler_ServeHTTP_DisabledDiscovery(t *testing.T) {
	c := &OCMProviderConfig{} // no endpoint
	deps := &deps.Deps{}

	h, err := newOCMHandler(c, deps, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var disc spec.Discovery
	if err := json.NewDecoder(w.Body).Decode(&disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if disc.Enabled {
		t.Error("expected Enabled=false in response")
	}
}
