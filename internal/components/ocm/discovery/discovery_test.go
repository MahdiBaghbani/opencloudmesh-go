package discovery_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestCriteriaAlwaysPresent(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:    true,
		APIVersion: "1.4.0",
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

func TestDiscovery_Helpers(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:    true,
		APIVersion: "1.4.0",
		EndPoint:   "https://example.com/ocm",
		ResourceTypes: []spec.ResourceType{
			{
				Name:       "file",
				ShareTypes: []string{"user"},
				Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm/")},
			},
		},
		Capabilities: []string{"http-sig", "exchange-token"},
		Criteria:     []string{spec.CriteriaMustUseHTTPSig},
	}

	if disc.GetWebDAVPath() != "/webdav/ocm/" {
		t.Errorf("GetWebDAVPath failed: %q", disc.GetWebDAVPath())
	}
	if !disc.HasCriteria(spec.CriteriaMustUseHTTPSig) {
		t.Error("HasCriteria must-use-http-sig should be true")
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
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      strings.TrimSuffix(server.URL, "/") + "/ocm",
				ResourceTypes: []spec.ResourceType{},
				Criteria:      []string{},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(disc)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	httpCfg := tshttp.PermissiveConfig()
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

// inlineKeyDiscoveryPayload builds a raw discovery JSON document carrying
// inline key material in either the singular publicKey wire shape or the
// plural publicKeys wire shape.
func inlineKeyDiscoveryPayload(serverURL, shape, apiVersion string) map[string]any {
	endpoint := strings.TrimSuffix(serverURL, "/") + "/ocm"
	raw := map[string]any{
		"enabled":       true,
		"apiVersion":    apiVersion,
		"endPoint":      endpoint,
		"resourceTypes": []any{},
		"criteria":      []any{},
		"capabilities":  []string{"http-sig"},
	}
	switch shape {
	case "singular":
		raw["publicKey"] = map[string]string{
			"keyId":        "https://peer.example.com/ocm#test-key",
			"publicKeyPem": "test-pem",
		}
	case "plural":
		raw["publicKeys"] = []map[string]string{{
			"keyId":        "https://peer.example.com/ocm#test-key",
			"publicKeyPem": "test-pem",
		}}
	}
	return raw
}

func TestClientDiscover_IgnoresInlinePublicKey(t *testing.T) {
	tests := []struct {
		name       string
		shape      string
		apiVersion string
		wantErr    bool
	}{
		{name: "singular_1.2.2", shape: "singular", apiVersion: "1.2.2", wantErr: false},
		{name: "plural_1.2.2", shape: "plural", apiVersion: "1.2.2", wantErr: false},
		{name: "singular_1.4.0", shape: "singular", apiVersion: "1.4.0", wantErr: false},
		{name: "plural_1.4.0", shape: "plural", apiVersion: "1.4.0", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/ocm" {
					http.NotFound(w, r)
					return
				}
				raw := inlineKeyDiscoveryPayload(server.URL, tt.shape, tt.apiVersion)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(raw)
			}))
			defer server.Close()

			httpCfg := tshttp.PermissiveConfig()
			client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

			disc, err := client.Discover(context.Background(), server.URL)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
					t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Discover failed: %v", err)
			}

			if tt.apiVersion != spec.APIVersionPin {
				found := false
				for _, w := range disc.Warnings {
					if strings.Contains(w, "differs from pin") {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("expected differs-from-pin warning for apiVersion %q, got %v", tt.apiVersion, disc.Warnings)
				}
			}

			out, err := json.Marshal(disc)
			if err != nil {
				t.Fatalf("marshal discovery: %v", err)
			}
			if strings.Contains(string(out), "test-pem") {
				t.Fatalf("expected no inline key material, got %s", out)
			}
		})
	}
}

func TestClientDiscover_CacheHitDoesNotRefetch(t *testing.T) {
	callCount := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		callCount++
		raw := map[string]any{
			"enabled":       true,
			"apiVersion":    "1.4.0",
			"endPoint":      strings.TrimSuffix(server.URL, "/") + "/ocm",
			"resourceTypes": []any{},
			"criteria":      []any{},
			"capabilities":  []string{"http-sig"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	}))
	defer server.Close()

	httpCfg := tshttp.PermissiveConfig()
	client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

	if _, err := client.Discover(context.Background(), server.URL); err != nil {
		t.Fatalf("first Discover failed: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected exactly 1 HTTP call, got %d", callCount)
	}

	if _, err := client.Discover(context.Background(), server.URL); err != nil {
		t.Fatalf("second Discover failed: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected cache hit to avoid a second HTTP call, call count %d", callCount)
	}
}
