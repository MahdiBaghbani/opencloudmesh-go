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
)

func TestClientDiscover_DeserializesTypedReceiveRoles(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"resourceTypes": []any{
				map[string]any{
					"name":       "file",
					"shareTypes": []string{"user"},
					"protocols": map[string]any{
						"webdav":         "/webdav/ocm/",
						"webdav-receive": map[string]string{"uri": "absolute"},
					},
				},
			},
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(disc.ResourceTypes) != 1 {
		t.Fatalf("resourceTypes len = %d", len(disc.ResourceTypes))
	}
	protocols := disc.ResourceTypes[0].Protocols
	path, ok := protocols.StringRole("webdav")
	if !ok || path != "/webdav/ocm/" {
		t.Fatalf("webdav = %q, ok=%v", path, ok)
	}
	wr, ok := protocols.WebDAVReceive()
	if !ok || wr.URI != "absolute" {
		t.Fatalf("webdav-receive = %+v, ok=%v", wr, ok)
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
