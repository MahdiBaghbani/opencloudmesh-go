package discovery_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestClientDiscover_RejectsMalformedProtocolRoles(t *testing.T) {
	httpCfg := tshttp.PermissiveConfig()

	t.Run("webdav-receive invalid uri kind", func(t *testing.T) {
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, map[string]any{
				"resourceTypes": []any{
					map[string]any{
						"name":       "file",
						"shareTypes": []string{"user"},
						"protocols": map[string]any{
							"webdav-receive": map[string]string{"uri": "invalid-kind"},
						},
					},
				},
			})

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(raw)
		})

		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Fatal("expected error for malformed webdav-receive uri")
		}

		if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
			t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
		}
	})

	t.Run("webdav non-string type", func(t *testing.T) {
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, map[string]any{
				"resourceTypes": []any{
					map[string]any{
						"name":       "file",
						"shareTypes": []string{"user"},
						"protocols": map[string]any{
							"webdav": map[string]any{},
						},
					},
				},
			})

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(raw)
		})

		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Fatal("expected error for webdav non-string type")
		}

		if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
			t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
		}
	})

	t.Run("webdav-receive non-object", func(t *testing.T) {
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, map[string]any{
				"resourceTypes": []any{
					map[string]any{
						"name":       "file",
						"shareTypes": []string{"user"},
						"protocols": map[string]any{
							"webdav-receive": "/not-an-object",
						},
					},
				},
			})

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(raw)
		})

		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Fatal("expected error for webdav-receive non-object")
		}

		if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
			t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
		}
	})

	t.Run("protocol role preserved but not locally shape-validated", func(t *testing.T) {
		roles := []struct {
			name string
			role any
		}{
			{name: "custom-proto", role: "/custom/path"},
			{name: "talk", role: map[string]string{"uri": "talk-v1"}},
			{name: "webapp", role: "/apps/ocm/"},
			{name: "ssh", role: "user@host"},
		}

		for _, tc := range roles {
			t.Run(tc.name, func(t *testing.T) {
				server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
					raw := validDiscoveryPayload(serverURL, map[string]any{
						"resourceTypes": []any{
							map[string]any{
								"name":       "file",
								"shareTypes": []string{"user"},
								"protocols": map[string]any{
									tc.name: tc.role,
								},
							},
						},
					})

					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(raw)
				})

				client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

				disc, err := client.Discover(context.Background(), server.URL)
				if err != nil {
					t.Fatalf("Discover failed: %v", err)
				}

				if len(disc.ResourceTypes) != 1 {
					t.Fatalf("resourceTypes len = %d", len(disc.ResourceTypes))
				}

				if _, ok := disc.ResourceTypes[0].Protocols[tc.name]; !ok {
					t.Fatalf("protocol role %q was dropped from Protocols", tc.name)
				}

				found := false

				want := "protocol role \"" + tc.name + "\" preserved but not locally shape-validated"
				for _, w := range disc.Warnings {
					if w == want {
						found = true
						break
					}
				}

				if !found {
					t.Fatalf("expected warning %q, got %v", want, disc.Warnings)
				}
			})
		}
	})
}
