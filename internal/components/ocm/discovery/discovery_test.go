package discovery_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/evaluator"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func ptrBool(b bool) *bool { return &b }

// Migrated from TestHandler_CriteriaAlwaysPresent -- now tests the spec type contract directly.
func TestCriteriaAlwaysPresent(t *testing.T) {
	disc := &discovery.Discovery{
		Enabled:    true,
		APIVersion: "1.2.2",
		Criteria:   []string{},
	}

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

// Migrated from TestHandler_CriteriaAdvertiseHTTPRequestSignatures -- now tests
// evaluator-driven criteria via the canonical three-dimension model.
func TestEvaluator_ReceiverStrictnessDrivesCriteria(t *testing.T) {
	t.Run("strict mode emits token-exchange criteria", func(t *testing.T) {
		cfg := &config.Config{
			TokenExchange:               config.TokenExchangeConfig{Enabled: ptrBool(true)},
			WebDAVTokenExchange:         config.WebDAVTokenExchangeConfig{Mode: "strict"},
			NonStrictPeerOutboundPolicy: "legacy-compatible",
		}
		eval := evaluator.NewLocalEvaluator(cfg).Evaluate()
		if !eval.ReceiverStrictness {
			t.Error("expected ReceiverStrictness true for strict mode")
		}
	})

	t.Run("lenient mode does not emit token-exchange criteria", func(t *testing.T) {
		cfg := &config.Config{
			TokenExchange:               config.TokenExchangeConfig{Enabled: ptrBool(true)},
			WebDAVTokenExchange:         config.WebDAVTokenExchangeConfig{Mode: "lenient"},
			NonStrictPeerOutboundPolicy: "legacy-compatible",
		}
		eval := evaluator.NewLocalEvaluator(cfg).Evaluate()
		if eval.ReceiverStrictness {
			t.Error("expected ReceiverStrictness false for lenient mode")
		}
	})
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

	if disc.GetEndpoint() != "https://example.com/ocm" {
		t.Errorf("GetEndpoint failed")
	}

	if disc.GetWebDAVPath() != "/webdav/ocm/" {
		t.Errorf("GetWebDAVPath failed: %q", disc.GetWebDAVPath())
	}

	if !disc.HasCapability("http-sig") {
		t.Error("HasCapability http-sig should be true")
	}
	if disc.HasCapability("unknown") {
		t.Error("HasCapability unknown should be false")
	}

	if !disc.HasCriteria("http-request-signatures") {
		t.Error("HasCriteria http-request-signatures should be true")
	}
	if disc.HasCriteria("unknown") {
		t.Error("HasCriteria unknown should be false")
	}

	pk := disc.GetPublicKey("key1")
	if pk == nil {
		t.Error("GetPublicKey key1 should return a key")
	}
	if disc.GetPublicKey("unknown") != nil {
		t.Error("GetPublicKey unknown should return nil")
	}

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
