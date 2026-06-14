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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestCriteriaAlwaysPresent(t *testing.T) {
	disc := &discovery.Discovery{
		Enabled:    true,
		APIVersion: "1.2.2",
		Criteria:   []string{},
	}

	if disc.Criteria == nil {
		t.Error("Criteria must not be nil")
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

func TestEvaluator_RequiresTokenExchangeDrivesCriteria(t *testing.T) {
	t.Run("require_token_exchange=true", func(t *testing.T) {
		tokenExchangeEnabled := true
		cfg := &config.Config{
			TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
			RequireTokenExchange: true,
			PeerPolicy:           "legacy",
		}
		eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()
		if !eval.RequiresTokenExchange {
			t.Error("expected RequiresTokenExchange true")
		}
	})

	t.Run("require_token_exchange=false", func(t *testing.T) {
		tokenExchangeEnabled := true
		cfg := &config.Config{
			TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
			RequireTokenExchange: false,
			PeerPolicy:           "legacy",
		}
		eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()
		if eval.RequiresTokenExchange {
			t.Error("expected RequiresTokenExchange false")
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
		Criteria:     []string{spec.CriteriaMustUseHTTPSig},
		PublicKeys: []discovery.PublicKey{
			{KeyID: "key1", PublicKeyPem: "..."},
		},
	}

	if disc.GetWebDAVPath() != "/webdav/ocm/" {
		t.Errorf("GetWebDAVPath failed: %q", disc.GetWebDAVPath())
	}
	if !disc.HasCriteria(spec.CriteriaMustUseHTTPSig) {
		t.Error("HasCriteria must-use-http-sig should be true")
	}
	if !disc.HasCriteria("http-request-signatures") {
		t.Error("HasCriteria legacy alias should be true")
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

	httpCfg := tshttp.PermissiveConfig()
	httpCfg.DerivedSSRFMode = "off"
	httpClient := httpclient.New(httpCfg, nil)
	client := discovery.NewClient(httpClient, nil)

	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if !disc.Enabled {
		t.Error("expected discovery to be enabled")
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

	httpCfg := tshttp.PermissiveConfig()
	httpCfg.DerivedSSRFMode = "off"
	client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(disc.PublicKeys) != 0 {
		t.Fatalf("expected legacy publicKey to stay disabled without compat, got %+v", disc.PublicKeys)
	}
}

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
				{Pattern: parsed.Hostname(), Profile: "compat"},
			},
		)
		contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
		if err != nil {
			t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
		}
		return contract
	}

	httpCfg := tshttp.PermissiveConfig()
	httpCfg.DerivedSSRFMode = "off"
	client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

	disc1, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover without compat failed: %v", err)
	}
	if len(disc1.PublicKeys) != 0 {
		t.Fatalf("expected empty publicKeys without compat, got %+v", disc1.PublicKeys)
	}
	if callCount != 1 {
		t.Fatalf("expected exactly 1 HTTP call, got %d", callCount)
	}

	client.SetPeerContract(buildContract(t))
	disc2, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover with compat contract failed: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("unexpected HTTP call after compat contract set, call count %d", callCount)
	}
	if len(disc2.PublicKeys) != 1 {
		t.Fatalf("expected legacy key promoted to publicKeys, got %+v", disc2.PublicKeys)
	}

	client.SetPeerContract(nil)
	disc3, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover after contract removed failed: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("unexpected HTTP call after contract removed, call count %d", callCount)
	}
	if len(disc3.PublicKeys) != 0 {
		t.Fatalf("expected empty publicKeys after contract removed, got %+v", disc3.PublicKeys)
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
			"criteria":      []any{spec.CriteriaMustUseHTTPSig},
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
			{Pattern: parsed.Hostname(), Profile: "compat"},
		},
	)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}

	httpCfg := tshttp.PermissiveConfig()
	httpCfg.DerivedSSRFMode = "off"
	client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
	client.SetPeerContract(contract)

	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(disc.PublicKeys) != 1 {
		t.Fatalf("expected legacy publicKey to normalize into one publicKeys entry, got %+v", disc.PublicKeys)
	}
}
