package discovery_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

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
