package discovery_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
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
