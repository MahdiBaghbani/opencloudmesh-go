package discovery_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func validDiscoveryPayload(serverURL string, extra map[string]any) map[string]any {
	endpoint := strings.TrimSuffix(serverURL, "/") + "/ocm"
	raw := map[string]any{
		"enabled":       true,
		"apiVersion":    "1.4.0",
		"endPoint":      endpoint,
		"resourceTypes": []any{},
		"criteria":      []any{},
	}
	for k, v := range extra {
		raw[k] = v
	}
	return raw
}

func newDiscoveryTestServer(t *testing.T, handler func(serverURL string, w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(srv.URL, w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

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

func TestClientDiscover_NormalizesRelativeInviteAcceptDialog(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"inviteAcceptDialog": "/apps/ocm/invite-accept",
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	want := strings.TrimSuffix(server.URL, "/") + "/apps/ocm/invite-accept"
	if disc.InviteAcceptDialog != want {
		t.Errorf("InviteAcceptDialog = %q, want %q", disc.InviteAcceptDialog, want)
	}
}

func TestClientDiscover_NormalizesRelativeInviteAcceptDialogWithoutEndPoint(t *testing.T) {
	server := newDiscoveryTestServer(t, func(_ string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		raw := map[string]any{
			"enabled":            true,
			"apiVersion":         "1.4.0",
			"resourceTypes":      []any{},
			"criteria":           []any{},
			"inviteAcceptDialog": "apps/ocm/invite-accept",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error when endPoint is missing")
	}
	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_CacheHit_NormalizesRelativeInviteAcceptDialogWithOriginBase(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected HTTP request on cache hit: %s", r.URL.Path)
	}))
	defer server.Close()

	baseURL := server.URL + "/tenant/instance"
	raw := validDiscoveryPayload(server.URL, map[string]any{
		"inviteAcceptDialog": "apps/ocm/invite-accept",
	})
	rawBytes, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal discovery: %v", err)
	}

	c := cache.NewDefault()
	cacheKey := "discovery:" + baseURL
	if err := c.Set(context.Background(), cacheKey, rawBytes, cache.TTLDiscovery); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), c)
	disc, err := client.Discover(context.Background(), baseURL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	want := server.URL + "/apps/ocm/invite-accept"
	if disc.InviteAcceptDialog != want {
		t.Errorf("InviteAcceptDialog = %q, want %q", disc.InviteAcceptDialog, want)
	}
}

func TestClientDiscover_EvictsStaleCacheEntryOnValidationFailure(t *testing.T) {
	var fetchCount int
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		fetchCount++
		raw := validDiscoveryPayload(serverURL, nil)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	c := cache.NewDefault()
	cacheKey := "discovery:" + server.URL
	invalidRaw, err := json.Marshal(validDiscoveryPayload(server.URL, map[string]any{
		"endPoint": "/ocm",
	}))
	if err != nil {
		t.Fatalf("marshal invalid discovery: %v", err)
	}
	if err := c.Set(context.Background(), cacheKey, invalidRaw, cache.TTLDiscovery); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), c)
	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if fetchCount != 1 {
		t.Fatalf("fetchCount = %d, want 1 after evicting stale cache entry", fetchCount)
	}
	wantEndpoint := strings.TrimSuffix(server.URL, "/") + "/ocm"
	if disc.EndPoint != wantEndpoint {
		t.Errorf("EndPoint = %q, want %q", disc.EndPoint, wantEndpoint)
	}

	fetchCount = 0
	disc2, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("second Discover failed: %v", err)
	}
	if fetchCount != 0 {
		t.Fatalf("fetchCount = %d, want 0 on validated cache hit", fetchCount)
	}
	if disc2.EndPoint != wantEndpoint {
		t.Errorf("cached EndPoint = %q, want %q", disc2.EndPoint, wantEndpoint)
	}
}

func TestClientDiscover_RejectsCrossAuthorityInviteAcceptDialog(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"inviteAcceptDialog": "https://custom.example.com/accept",
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for cross-authority inviteAcceptDialog")
	}
	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_AcceptsLowerAPIVersionWithWarning(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, nil)
		raw["apiVersion"] = "1.2.2"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(disc.Warnings) == 0 {
		t.Fatal("expected apiVersion warning in disc.Warnings")
	}
	found := false
	for _, w := range disc.Warnings {
		if strings.Contains(w, "differs from pin") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected differs-from-pin warning, got %v", disc.Warnings)
	}
}

func TestClientDiscover_RejectsAPIVersionUnderExactPolicy(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, nil)
		raw["apiVersion"] = "1.2.2"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	client.SetVersionPolicy(&discovery.VersionPolicy{
		Mode: discovery.APIVersionExact,
		Warn: discovery.WarnNone,
	})
	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for non-pin apiVersion under exact policy")
	}
	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_RejectsNonAbsoluteEndPoint(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, nil)
		raw["endPoint"] = "/ocm"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for non-absolute endPoint")
	}
	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_RejectsCrossAuthorityEndPoint(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, nil)
		raw["endPoint"] = "https://other.example.com/ocm"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for cross-authority endPoint")
	}
	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_RejectsExchangeTokenWithoutTokenEndPoint(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"capabilities": []string{"exchange-token"},
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for exchange-token without tokenEndPoint")
	}
	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_RejectsTokenEndPointWithoutExchangeTokenCapability(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"tokenEndPoint": strings.TrimSuffix(serverURL, "/") + "/token",
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for tokenEndPoint without exchange-token capability")
	}
	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_RejectsNonAbsoluteTokenEndPoint(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"capabilities":  []string{"exchange-token"},
			"tokenEndPoint": "/token",
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for non-absolute tokenEndPoint")
	}
	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_RejectsCrossAuthorityTokenEndPoint(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"capabilities":  []string{"exchange-token"},
			"tokenEndPoint": "https://other.example.com/token",
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for cross-authority tokenEndPoint")
	}
	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

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

func TestClientDiscover_ErrorsIsThroughDiscoverWrap(t *testing.T) {
	httpCfg := tshttp.PermissiveConfig()
	t.Run("not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer server.Close()

		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, discovery.ErrDiscoveryNotFound) {
			t.Fatalf("errors.Is(err, ErrDiscoveryNotFound) = false, err = %v", err)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/ocm" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{not-json"))
		}))
		defer server.Close()

		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
			t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/ocm" {
				http.NotFound(w, r)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"enabled":       false,
				"apiVersion":    "1.4.0",
				"resourceTypes": []any{},
				"criteria":      []any{},
			})
		}))
		defer server.Close()

		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, discovery.ErrOCMDisabled) {
			t.Fatalf("errors.Is(err, ErrOCMDisabled) = false, err = %v", err)
		}
	})
}

func TestClientDiscover_VersionPolicyModes(t *testing.T) {
	httpCfg := tshttp.PermissiveConfig()

	t.Run("exact rejects 1.3.0", func(t *testing.T) {
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, nil)
			raw["apiVersion"] = "1.3.0"
			json.NewEncoder(w).Encode(raw)
		})
		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
		client.SetVersionPolicy(&discovery.VersionPolicy{
			Mode: discovery.APIVersionExact,
			Warn: discovery.WarnNone,
		})
		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Fatal("expected rejection under exact policy")
		}
	})

	t.Run("at-least-1.4 accepts 1.4.0 and 2.0.0 rejects 1.3.0", func(t *testing.T) {
		policy := &discovery.VersionPolicy{
			Mode: discovery.APIVersionAtLeast14,
			Warn: discovery.WarnNone,
		}
		for _, v := range []string{"1.4.0", "2.0.0"} {
			t.Run("accept_"+v, func(t *testing.T) {
				server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
					raw := validDiscoveryPayload(serverURL, nil)
					raw["apiVersion"] = v
					json.NewEncoder(w).Encode(raw)
				})
				client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
				client.SetVersionPolicy(policy)
				if _, err := client.Discover(context.Background(), server.URL); err != nil {
					t.Fatalf("Discover(%s) failed: %v", v, err)
				}
			})
		}
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, nil)
			raw["apiVersion"] = "1.3.0"
			json.NewEncoder(w).Encode(raw)
		})
		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
		client.SetVersionPolicy(policy)
		if _, err := client.Discover(context.Background(), server.URL); err == nil {
			t.Fatal("expected rejection for 1.3.0 under at-least-1.4")
		}
	})

	t.Run("accept-any accepts all non-empty", func(t *testing.T) {
		for _, v := range []string{"1.1.0", "1.3.0", "2.0.0"} {
			t.Run(v, func(t *testing.T) {
				server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
					raw := validDiscoveryPayload(serverURL, nil)
					raw["apiVersion"] = v
					json.NewEncoder(w).Encode(raw)
				})
				client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
				if _, err := client.Discover(context.Background(), server.URL); err != nil {
					t.Fatalf("Discover(%s) failed: %v", v, err)
				}
			})
		}
	})
}

func TestClientDiscover_WarnModesUnderAcceptAny(t *testing.T) {
	httpCfg := tshttp.PermissiveConfig()

	t.Run("any-diff warns on 1.3.0 and 2.0.0", func(t *testing.T) {
		policy := &discovery.VersionPolicy{Mode: discovery.APIVersionAcceptAny, Warn: discovery.WarnAnyDiff}
		for _, v := range []string{"1.3.0", "2.0.0"} {
			t.Run(v, func(t *testing.T) {
				server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
					raw := validDiscoveryPayload(serverURL, nil)
					raw["apiVersion"] = v
					json.NewEncoder(w).Encode(raw)
				})
				client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
				client.SetVersionPolicy(policy)
				disc, err := client.Discover(context.Background(), server.URL)
				if err != nil {
					t.Fatalf("Discover failed: %v", err)
				}
				if !hasWarningSubstring(disc.Warnings, "differs from pin") {
					t.Fatalf("expected differs-from-pin warning for %s, got %v", v, disc.Warnings)
				}
			})
		}
	})

	t.Run("lower-only warns on 1.3.0 not 2.0.0", func(t *testing.T) {
		policy := &discovery.VersionPolicy{Mode: discovery.APIVersionAcceptAny, Warn: discovery.WarnLowerOnly}
		serverLow := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, nil)
			raw["apiVersion"] = "1.3.0"
			json.NewEncoder(w).Encode(raw)
		})
		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
		client.SetVersionPolicy(policy)
		disc, err := client.Discover(context.Background(), serverLow.URL)
		if err != nil {
			t.Fatalf("Discover failed: %v", err)
		}
		if len(disc.Warnings) == 0 {
			t.Fatal("expected lower-only warning for 1.3.0")
		}

		serverHigh := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, nil)
			raw["apiVersion"] = "2.0.0"
			json.NewEncoder(w).Encode(raw)
		})
		client2 := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
		client2.SetVersionPolicy(policy)
		disc2, err := client2.Discover(context.Background(), serverHigh.URL)
		if err != nil {
			t.Fatalf("Discover failed: %v", err)
		}
		for _, w := range disc2.Warnings {
			if strings.Contains(w, "lower than pin") {
				t.Fatalf("unexpected lower warning for 2.0.0: %v", disc2.Warnings)
			}
		}
	})

	t.Run("none never warns", func(t *testing.T) {
		policy := &discovery.VersionPolicy{Mode: discovery.APIVersionAcceptAny, Warn: discovery.WarnNone}
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, nil)
			raw["apiVersion"] = "1.3.0"
			json.NewEncoder(w).Encode(raw)
		})
		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
		client.SetVersionPolicy(policy)
		disc, err := client.Discover(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("Discover failed: %v", err)
		}
		if len(disc.Warnings) != 0 {
			t.Fatalf("expected no warnings, got %v", disc.Warnings)
		}
	})
}

func TestClientDiscover_FreshFetchOnlyLogsWarnings(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"apiVersion": "1.2.2",
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	c := cache.NewDefault()
	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), c)
	client.SetLogger(logger)

	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("first Discover failed: %v", err)
	}
	if !hasWarningSubstring(disc.Warnings, "differs from pin") {
		t.Fatalf("expected differs-from-pin warning in result, got %v", disc.Warnings)
	}
	firstLog := buf.String()
	if !strings.Contains(firstLog, "discovery warning") {
		t.Fatalf("fresh fetch log missing discovery warning marker, got %q", firstLog)
	}
	if !strings.Contains(firstLog, "differs from pin") {
		t.Fatalf("fresh fetch log missing warning text, got %q", firstLog)
	}

	buf.Reset()
	disc2, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("second Discover failed: %v", err)
	}
	if !hasWarningSubstring(disc2.Warnings, "differs from pin") {
		t.Fatalf("cache hit missing warning in result, got %v", disc2.Warnings)
	}
	if buf.Len() != 0 {
		t.Fatalf("cache hit logged warnings again: %q", buf.String())
	}
}

func TestClientDiscover_WarningsOwnershipAndJSONOmission(t *testing.T) {
	httpCfg := tshttp.PermissiveConfig()
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"apiVersion": "1.3.0",
			"resourceTypes": []any{
				map[string]any{
					"name":       "file",
					"shareTypes": []string{"user"},
					"protocols": map[string]any{
						"talk": map[string]string{"uri": "talk-v1"},
					},
				},
			},
		})
		json.NewEncoder(w).Encode(raw)
	})

	c := cache.NewDefault()
	client := discovery.NewClient(httpclient.New(httpCfg, nil), c)

	disc1, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("first Discover failed: %v", err)
	}
	if len(disc1.Warnings) < 2 {
		t.Fatalf("expected apiVersion and protocol warnings, got %v", disc1.Warnings)
	}

	out, err := json.Marshal(disc1)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "Warnings") || strings.Contains(string(out), "differs from pin") {
		t.Fatalf("marshaled discovery must omit Warnings, got %s", out)
	}

	disc2, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("second Discover failed: %v", err)
	}
	if len(disc2.Warnings) != len(disc1.Warnings) {
		t.Fatalf("cache hit warnings len = %d, want %d (no duplicate accumulation)", len(disc2.Warnings), len(disc1.Warnings))
	}
}

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

func hasWarningSubstring(warnings []string, sub string) bool {
	for _, w := range warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}
