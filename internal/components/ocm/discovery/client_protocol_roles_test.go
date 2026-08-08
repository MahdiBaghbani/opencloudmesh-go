// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestClientDiscover_RejectsMalformedProtocolRoles(t *testing.T) {
	t.Parallel()

	httpCfg := tshttp.PermissiveConfig()

	t.Run("webdav-receive invalid uri kind", func(t *testing.T) {
		t.Parallel()
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, _ *http.Request) {
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
			tshttp.MustEncodeJSON(t, w, raw)
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
		t.Parallel()
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, _ *http.Request) {
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
			tshttp.MustEncodeJSON(t, w, raw)
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
		t.Parallel()
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, _ *http.Request) {
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
			tshttp.MustEncodeJSON(t, w, raw)
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
		t.Parallel()

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
				t.Parallel()
				server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, _ *http.Request) {
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
					tshttp.MustEncodeJSON(t, w, raw)
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

				want := "protocol role \"" + tc.name + "\" preserved but not locally shape-validated"
				if !slices.Contains(disc.Warnings, want) {
					t.Fatalf("expected warning %q, got %v", want, disc.Warnings)
				}
			})
		}
	})
}
