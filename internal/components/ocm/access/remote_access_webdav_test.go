package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func sharedSecretDiscoveryHandler(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/.well-known/ocm" {
		return false
	}

	disc := spec.Discovery{
		Enabled:    true,
		APIVersion: "1.4.0",
		EndPoint:   "http://" + r.Host + "/ocm",
		ResourceTypes: []spec.ResourceType{
			{
				Name:       "file",
				ShareTypes: []string{"user"},
				Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(disc) //nolint:errcheck // test mock handler: JSON encode

	return true
}

func TestAccess_SharedSecretSuccess(t *testing.T) {
	var webdavHits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sharedSecretDiscoveryHandler(w, r) {
			return
		}

		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			webdavHits.Add(1)

			if r.Header.Get("Authorization") == "Bearer shared-secret" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("file content")) //nolint:errcheck // test mock handler: response write

				return
			}

			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := newExchangeAccessClient(t, srv)

	result, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   srv.URL,
			SharedSecret: "shared-secret",
			WebDAVID:     "file-123",
		},
		Protocol: "webdav",
		Method:   "GET",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer result.Response.Body.Close() //nolint:errcheck // test cleanup: resource close

	if result.Response.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", result.Response.StatusCode, http.StatusOK)
	}

	if got := webdavHits.Load(); got != 1 {
		t.Errorf("webdav hits = %d, want 1", got)
	}

	if result.AccessToken != "shared-secret" {
		t.Errorf("AccessToken = %q, want shared-secret", result.AccessToken)
	}
}
