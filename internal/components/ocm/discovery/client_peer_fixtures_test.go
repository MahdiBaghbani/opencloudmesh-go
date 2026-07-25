package discovery_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestClientDiscover_RealPeerFixtures(t *testing.T) {
	httpCfg := tshttp.PermissiveConfig()
	fixtures := []struct {
		name       string
		apiVersion string
		protocols  map[string]any
	}{
		{
			name:       "nextcloud_1.0-proposal1_talk-v1",
			apiVersion: "1.0-proposal1",
			protocols: map[string]any{
				"webdav": "/remote.php/dav/ocm/",
				"talk":   map[string]string{"uri": "talk-v1"},
			},
		},
		{
			name:       "ocis_1.1.0",
			apiVersion: "1.1.0",
			protocols: map[string]any{
				"webdav": "/dav/ocm/",
			},
		},
		{
			name:       "opencloud_1.2.0",
			apiVersion: "1.2.0",
			protocols: map[string]any{
				"webdav": "/webdav/ocm/",
			},
		},
	}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
				raw := validDiscoveryPayload(serverURL, map[string]any{
					"apiVersion": fx.apiVersion,
					"resourceTypes": []any{
						map[string]any{
							"name":       "file",
							"shareTypes": []string{"user"},
							"protocols":  fx.protocols,
						},
					},
				})
				json.NewEncoder(w).Encode(raw)
			})
			client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
			disc, err := client.Discover(context.Background(), server.URL)
			if err != nil {
				t.Fatalf("Discover failed: %v", err)
			}
			if len(disc.Warnings) == 0 {
				t.Fatal("expected warnings for real-peer fixture")
			}
			if fx.apiVersion != spec.APIVersionPin && !hasWarningSubstring(disc.Warnings, "differs from pin") {
				t.Fatalf("expected differs-from-pin warning, got %v", disc.Warnings)
			}
		})
	}
}
