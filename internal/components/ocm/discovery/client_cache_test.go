package discovery_test

import (
	"context"
	"encoding/json"
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
