package discovery_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestHandler_GetDiscovery(t *testing.T) {
	cfg := &config.Config{
		PublicOrigin:   "https://example.com",
		ExternalBasePath: "/ocm-app",
	}

	handler := discovery.NewHandler(cfg)
	disc := handler.GetDiscovery()

	if !disc.Enabled {
		t.Error("expected enabled=true")
	}
	if disc.APIVersion != "1.2.2" {
		t.Errorf("expected apiVersion '1.2.2', got %q", disc.APIVersion)
	}
	if disc.EndPoint != "https://example.com/ocm-app/ocm" {
		t.Errorf("expected endpoint 'https://example.com/ocm-app/ocm', got %q", disc.EndPoint)
	}
	if disc.Provider != "OpenCloudMesh" {
		t.Errorf("expected provider 'OpenCloudMesh', got %q", disc.Provider)
	}

	if len(disc.ResourceTypes) != 1 {
		t.Fatalf("expected 1 resource type, got %d", len(disc.ResourceTypes))
	}
	rt := disc.ResourceTypes[0]
	if rt.Name != "file" {
		t.Errorf("expected resource type 'file', got %q", rt.Name)
	}
	if len(rt.ShareTypes) != 1 || rt.ShareTypes[0] != "user" {
		t.Errorf("expected shareTypes ['user'], got %v", rt.ShareTypes)
	}
	if rt.Protocols["webdav"] != "/ocm-app/webdav/ocm/" {
		t.Errorf("expected webdav path '/ocm-app/webdav/ocm/', got %q", rt.Protocols["webdav"])
	}
}

func TestHandler_ServeHTTP(t *testing.T) {
	cfg := &config.Config{
		PublicOrigin:   "https://example.com",
		ExternalBasePath: "",
	}

	handler := discovery.NewHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", contentType)
	}

	var disc discovery.Discovery
	if err := json.NewDecoder(w.Body).Decode(&disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !disc.Enabled {
		t.Error("expected enabled=true in response")
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	cfg := &config.Config{}
	handler := discovery.NewHandler(cfg)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestHandler_SetPublicKeys(t *testing.T) {
	cfg := &config.Config{
		PublicOrigin: "https://example.com",
	}

	handler := discovery.NewHandler(cfg)

	disc := handler.GetDiscovery()
	if len(disc.PublicKeys) != 0 {
		t.Errorf("expected 0 public keys initially, got %d", len(disc.PublicKeys))
	}
	if disc.HasCapability("http-sig") {
		t.Error("should not have http-sig capability without keys")
	}

	handler.SetPublicKeys([]discovery.PublicKey{
		{
			KeyID:        "https://example.com/ocm#key1",
			PublicKeyPem: "-----BEGIN PUBLIC KEY-----\nMII...\n-----END PUBLIC KEY-----",
			Algorithm:    "ed25519",
		},
	})

	disc = handler.GetDiscovery()
	if len(disc.PublicKeys) != 1 {
		t.Errorf("expected 1 public key, got %d", len(disc.PublicKeys))
	}
	if !disc.HasCapability("http-sig") {
		t.Error("should have http-sig capability with keys")
	}
}

func TestHandler_CriteriaAlwaysPresent(t *testing.T) {
	cfg := &config.Config{
		PublicOrigin: "https://example.com",
		Signature: config.SignatureConfig{
			AdvertiseHTTPRequestSignatures: false,
		},
	}

	handler := discovery.NewHandler(cfg)
	disc := handler.GetDiscovery()

	if disc.Criteria == nil {
		t.Error("Criteria must not be nil")
	}

	if len(disc.Criteria) != 0 {
		t.Errorf("expected empty criteria, got %v", disc.Criteria)
	}

	data, err := json.Marshal(disc)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	if !json.Valid(data) {
		t.Error("invalid JSON")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	criteriaRaw, ok := parsed["criteria"]
	if !ok {
		t.Error("criteria key must be present in JSON")
	}

	criteriaSlice, ok := criteriaRaw.([]interface{})
	if !ok {
		t.Errorf("criteria must be an array, got %T", criteriaRaw)
	}
	if len(criteriaSlice) != 0 {
		t.Errorf("expected empty criteria array, got %v", criteriaSlice)
	}
}

func TestHandler_CriteriaAdvertiseHTTPRequestSignatures(t *testing.T) {
	cfg := &config.Config{
		PublicOrigin: "https://example.com",
		Signature: config.SignatureConfig{
			AdvertiseHTTPRequestSignatures: true,
		},
	}

	handler := discovery.NewHandler(cfg)
	disc := handler.GetDiscovery()

	if len(disc.Criteria) != 1 {
		t.Fatalf("expected 1 criteria token, got %d", len(disc.Criteria))
	}
	if disc.Criteria[0] != "http-request-signatures" {
		t.Errorf("expected 'http-request-signatures', got %q", disc.Criteria[0])
	}

	if !disc.HasCriteria("http-request-signatures") {
		t.Error("HasCriteria should return true for http-request-signatures")
	}
	if disc.HasCriteria("unknown-token") {
		t.Error("HasCriteria should return false for unknown token")
	}
}

func TestDiscovery_Helpers(t *testing.T) {
	disc := &discovery.Discovery{
		Enabled:    true,
		APIVersion: "1.2.2",
		EndPoint:   "https://example.com/ocm",
		ResourceTypes: []discovery.ResourceType{
			{
				Name:       "file",
				ShareTypes: []string{"user"},
				Protocols:  map[string]string{"webdav": "/webdav/ocm/"},
			},
		},
		Capabilities: []string{"http-sig", "exchange-token"},
		Criteria:     []string{"http-request-signatures"},
		PublicKeys: []discovery.PublicKey{
			{KeyID: "key1", PublicKeyPem: "..."},
		},
	}

	// GetEndpoint
	if disc.GetEndpoint() != "https://example.com/ocm" {
		t.Errorf("GetEndpoint failed")
	}

	// GetWebDAVPath
	if disc.GetWebDAVPath() != "/webdav/ocm/" {
		t.Errorf("GetWebDAVPath failed: %q", disc.GetWebDAVPath())
	}

	// HasCapability
	if !disc.HasCapability("http-sig") {
		t.Error("HasCapability http-sig should be true")
	}
	if disc.HasCapability("unknown") {
		t.Error("HasCapability unknown should be false")
	}

	// HasCriteria
	if !disc.HasCriteria("http-request-signatures") {
		t.Error("HasCriteria http-request-signatures should be true")
	}
	if disc.HasCriteria("unknown") {
		t.Error("HasCriteria unknown should be false")
	}

	// GetPublicKey
	pk := disc.GetPublicKey("key1")
	if pk == nil {
		t.Error("GetPublicKey key1 should return a key")
	}
	if disc.GetPublicKey("unknown") != nil {
		t.Error("GetPublicKey unknown should return nil")
	}

	// BuildWebDAVURL
	url, err := disc.BuildWebDAVURL("abc123")
	if err != nil {
		t.Fatalf("BuildWebDAVURL failed: %v", err)
	}
	if url != "https://example.com/webdav/ocm/abc123" {
		t.Errorf("BuildWebDAVURL returned %q", url)
	}
}

func TestNewClient_NilCacheDefaultsToMemory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := discovery.Discovery{
				Enabled:    true,
				APIVersion: "1.2.2",
				EndPoint:   "https://example.com/ocm",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(disc)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	httpCfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	httpClient := httpclient.New(httpCfg, nil)
	client := discovery.NewClient(httpClient, nil)

	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if !disc.Enabled {
		t.Error("expected discovery to be enabled")
	}

	disc2, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("second Discover failed: %v", err)
	}
	if disc2.EndPoint != disc.EndPoint {
		t.Error("expected same discovery result from cache")
	}
}
