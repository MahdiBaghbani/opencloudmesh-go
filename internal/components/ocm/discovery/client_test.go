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
						"webapp-receive": map[string]any{"targets": []string{"blank", "iframe"}},
						"webapp":         map[string]any{},
						"ssh-receive":    map[string]any{},
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
	war, ok := protocols.WebAppReceive()
	if !ok || len(war.Targets) != 2 {
		t.Fatalf("webapp-receive = %+v, ok=%v", war, ok)
	}
	if !protocols["webapp"].IsEmptyObject() {
		t.Error("expected empty webapp object")
	}
	if !protocols["ssh-receive"].IsEmptyObject() {
		t.Error("expected empty ssh-receive object")
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

func TestClientDiscover_RejectsNon140APIVersion(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, nil)
		raw["apiVersion"] = "1.2.2"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for non-1.4.0 apiVersion")
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

	t.Run("webapp-receive missing targets", func(t *testing.T) {
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, map[string]any{
				"resourceTypes": []any{
					map[string]any{
						"name":       "file",
						"shareTypes": []string{"user"},
						"protocols": map[string]any{
							"webapp-receive": map[string]any{},
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
			t.Fatal("expected error for webapp-receive missing targets")
		}
		if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
			t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
		}
	})

	t.Run("talk non-string", func(t *testing.T) {
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, map[string]any{
				"resourceTypes": []any{
					map[string]any{
						"name":       "file",
						"shareTypes": []string{"user"},
						"protocols": map[string]any{
							"talk": map[string]any{},
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
			t.Fatal("expected error for talk non-string type")
		}
		if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
			t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
		}
	})

	t.Run("webapp non-empty object", func(t *testing.T) {
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, map[string]any{
				"resourceTypes": []any{
					map[string]any{
						"name":       "file",
						"shareTypes": []string{"user"},
						"protocols": map[string]any{
							"webapp": map[string]any{"uri": "/apps/ocm"},
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
			t.Fatal("expected error for non-empty webapp object")
		}
		if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
			t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
		}
	})

	t.Run("ssh-receive non-empty object", func(t *testing.T) {
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, map[string]any{
				"resourceTypes": []any{
					map[string]any{
						"name":       "file",
						"shareTypes": []string{"user"},
						"protocols": map[string]any{
							"ssh-receive": map[string]any{"uri": "absolute"},
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
			t.Fatal("expected error for non-empty ssh-receive object")
		}
		if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
			t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
		}
	})
}

func TestClientDiscover_NoLegacyFallback(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			http.NotFound(w, r)
		case "/ocm-provider":
			raw := validDiscoveryPayload(serverURL, nil)
			raw["apiVersion"] = "1.2.2"
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(raw)
		default:
			http.NotFound(w, r)
		}
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error when canonical discovery is missing")
	}
	if !errors.Is(err, discovery.ErrDiscoveryNotFound) {
		t.Fatalf("errors.Is(err, ErrDiscoveryNotFound) = false, err = %v", err)
	}
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
