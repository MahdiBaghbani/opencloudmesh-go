package discovery_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

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
func TestEvaluator_RequiresTokenExchangeDrivesCriteria(t *testing.T) {
	t.Run("require_token_exchange=true emits token-exchange criteria", func(t *testing.T) {
		tokenExchangeEnabled := true
		cfg := &config.Config{
			TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
			RequireTokenExchange: true,
			PeerPolicy:           "legacy",
		}
		eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()
		if !eval.RequiresTokenExchange {
			t.Error("expected RequiresTokenExchange true for require_token_exchange=true")
		}
	})

	t.Run("require_token_exchange=false does not emit token-exchange criteria", func(t *testing.T) {
		tokenExchangeEnabled := true
		cfg := &config.Config{
			TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
			RequireTokenExchange: false,
			PeerPolicy:           "legacy",
		}
		eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()
		if eval.RequiresTokenExchange {
			t.Error("expected RequiresTokenExchange false for require_token_exchange=false")
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

func TestClientDiscover_RejectsLegacyPublicKeyWithoutCompat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		raw := map[string]any{
			"enabled":       true,
			"apiVersion":    "1.2.2",
			"endPoint":      "https://peer.example.com/ocm",
			"resourceTypes": []any{},
			"criteria":      []any{},
			"capabilities":  []string{"http-sig"},
			"publicKey": map[string]string{
				"keyId":        "https://peer.example.com/ocm#legacy",
				"publicKeyPem": "legacy-pem",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	}))
	defer server.Close()

	httpCfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(disc.PublicKeys) != 0 {
		t.Fatalf("expected legacy publicKey to stay disabled without compat, got %+v", disc.PublicKeys)
	}
}

// TestClientDiscover_CacheContractDrift proves that the discovery cache stores
// raw response bytes, so normalization always reflects the current peer contract
// rather than the contract that was active at fetch time.
//
// Sequence:
//  1. Fetch with no compat contract -> publicKeys empty, raw bytes cached.
//  2. Set compat contract (same client, no new HTTP call) -> cache hit re-normalizes
//     -> legacy publicKey promoted into publicKeys.
//  3. Remove contract -> cache hit re-normalizes again -> publicKeys empty.
func TestClientDiscover_CacheContractDrift(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		callCount++
		raw := map[string]any{
			"enabled":       true,
			"apiVersion":    "1.2.2",
			"endPoint":      "https://peer.example.com/ocm",
			"resourceTypes": []any{},
			"criteria":      []any{},
			"capabilities":  []string{"http-sig"},
			"publicKey": map[string]string{
				"keyId":        "https://peer.example.com/ocm#legacy",
				"publicKeyPem": "legacy-pem",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	buildContract := func(t *testing.T) *peercompat.CompiledContract {
		t.Helper()
		registry := peercompat.NewProfileRegistry(
			map[string]*peercompat.Profile{
				"compat": {
					Name:                           "compat",
					AcceptLegacyDiscoveryPublicKey: true,
				},
			},
			[]peercompat.ProfileMapping{
				{Pattern: parsed.Hostname(), ProfileName: "compat"},
			},
		)
		contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
		if err != nil {
			t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
		}
		return contract
	}

	httpCfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

	// Step 1: no compat contract -> legacy key must NOT be promoted.
	disc1, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("step 1 Discover failed: %v", err)
	}
	if len(disc1.PublicKeys) != 0 {
		t.Fatalf("step 1: expected empty publicKeys without compat, got %+v", disc1.PublicKeys)
	}
	if callCount != 1 {
		t.Fatalf("step 1: expected exactly 1 HTTP call, got %d", callCount)
	}

	// Step 2: add compat contract; same client, no new HTTP call (cache hit).
	// Re-normalization must now promote the legacy key.
	client.SetPeerContract(buildContract(t))
	disc2, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("step 2 Discover failed: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("step 2: unexpected HTTP call (should have used cache), call count %d", callCount)
	}
	if len(disc2.PublicKeys) != 1 {
		t.Fatalf("step 2: expected legacy key promoted to publicKeys, got %+v", disc2.PublicKeys)
	}
	if disc2.PublicKeys[0].KeyID != "https://peer.example.com/ocm#legacy" {
		t.Fatalf("step 2: unexpected key ID %q", disc2.PublicKeys[0].KeyID)
	}

	// Step 3: remove compat contract; cache hit must re-normalize without compat.
	client.SetPeerContract(nil)
	disc3, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("step 3 Discover failed: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("step 3: unexpected HTTP call (should have used cache), call count %d", callCount)
	}
	if len(disc3.PublicKeys) != 0 {
		t.Fatalf("step 3: expected empty publicKeys after contract removed, got %+v", disc3.PublicKeys)
	}
}

func TestClientDiscover_AllowsLegacyPublicKeyWithPeerCompat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		raw := map[string]any{
			"enabled":       true,
			"apiVersion":    "1.2.2",
			"endPoint":      "https://peer.example.com/ocm",
			"resourceTypes": []any{},
			"criteria":      []any{"http-request-signatures"},
			"capabilities":  []string{"http-sig"},
			"publicKey": map[string]string{
				"keyId":        "https://peer.example.com/ocm#legacy",
				"publicKeyPem": "legacy-pem",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}
	registry := peercompat.NewProfileRegistry(
		map[string]*peercompat.Profile{
			"compat": {
				Name:                           "compat",
				AcceptLegacyDiscoveryPublicKey: true,
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: parsed.Hostname(), ProfileName: "compat"},
		},
	)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}

	httpCfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
	client.SetPeerContract(contract)

	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(disc.PublicKeys) != 1 {
		t.Fatalf("expected legacy publicKey to normalize into one publicKeys entry, got %+v", disc.PublicKeys)
	}
	if disc.PublicKeys[0].KeyID != "https://peer.example.com/ocm#legacy" {
		t.Fatalf("unexpected key ID %q", disc.PublicKeys[0].KeyID)
	}
	if disc.PublicKeys[0].Algorithm != "rsa" {
		t.Fatalf("expected normalized legacy key algorithm rsa, got %q", disc.PublicKeys[0].Algorithm)
	}
}
