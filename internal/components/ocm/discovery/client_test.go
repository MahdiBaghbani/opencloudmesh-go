package discovery_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestClientDiscover_DeserializesTypedReceiveRoles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		raw := map[string]any{
			"enabled":    true,
			"apiVersion": "1.4.0",
			"endPoint":   "https://peer.example.com/ocm",
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
			"criteria": []any{},
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		raw := map[string]any{
			"enabled":            true,
			"apiVersion":         "1.2.2",
			"endPoint":           "https://peer.example.com/ocm",
			"resourceTypes":      []any{},
			"criteria":           []any{},
			"inviteAcceptDialog": "/apps/ocm/invite-accept",
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
	want := "https://peer.example.com/apps/ocm/invite-accept"
	if disc.InviteAcceptDialog != want {
		t.Errorf("InviteAcceptDialog = %q, want %q", disc.InviteAcceptDialog, want)
	}
}

func TestClientDiscover_NormalizesRelativeInviteAcceptDialogWithoutEndPoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		raw := map[string]any{
			"enabled":            true,
			"apiVersion":         "1.2.2",
			"resourceTypes":      []any{},
			"criteria":           []any{},
			"inviteAcceptDialog": "apps/ocm/invite-accept",
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
	want := server.URL + "/apps/ocm/invite-accept"
	if disc.InviteAcceptDialog != want {
		t.Errorf("InviteAcceptDialog = %q, want %q", disc.InviteAcceptDialog, want)
	}
}

func TestClientDiscover_CacheHit_NormalizesRelativeInviteAcceptDialogWithOriginBase(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected HTTP request on cache hit: %s", r.URL.Path)
	}))
	defer server.Close()

	baseURL := server.URL + "/tenant/instance"
	raw := map[string]any{
		"enabled":            true,
		"apiVersion":         "1.2.2",
		"resourceTypes":      []any{},
		"criteria":           []any{},
		"inviteAcceptDialog": "apps/ocm/invite-accept",
	}
	rawBytes, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal discovery: %v", err)
	}

	c := cache.NewDefault()
	cacheKey := "discovery:" + baseURL
	if err := c.Set(context.Background(), cacheKey, rawBytes, cache.TTLDiscovery); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	httpCfg := tshttp.PermissiveConfig()
	httpCfg.DerivedSSRFMode = "off"
	client := discovery.NewClient(httpclient.New(httpCfg, nil), c)

	disc, err := client.Discover(context.Background(), baseURL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	want := server.URL + "/apps/ocm/invite-accept"
	if disc.InviteAcceptDialog != want {
		t.Errorf("InviteAcceptDialog = %q, want %q", disc.InviteAcceptDialog, want)
	}
}

func TestClientDiscover_PreservesAbsoluteInviteAcceptDialog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		raw := map[string]any{
			"enabled":            true,
			"apiVersion":         "1.2.2",
			"endPoint":           "https://peer.example.com/ocm",
			"resourceTypes":      []any{},
			"criteria":           []any{},
			"inviteAcceptDialog": "https://custom.example.com/accept",
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
	if disc.InviteAcceptDialog != "https://custom.example.com/accept" {
		t.Errorf("InviteAcceptDialog = %q", disc.InviteAcceptDialog)
	}
}

func TestClientDiscover_NoLegacyFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			http.NotFound(w, r)
		case "/ocm-provider":
			raw := map[string]any{
				"enabled":       true,
				"apiVersion":    "1.2.2",
				"endPoint":      "https://peer.example.com/ocm",
				"resourceTypes": []any{},
				"criteria":      []any{},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(raw)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	httpCfg := tshttp.PermissiveConfig()
	httpCfg.DerivedSSRFMode = "off"
	client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

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
	httpCfg.DerivedSSRFMode = "off"

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
				"apiVersion":    "1.2.2",
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
