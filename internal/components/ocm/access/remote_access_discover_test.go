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

func TestAccess_PrefetchSingleDiscover(t *testing.T) {
	const exchangedToken = "exchanged-access-token"

	var discoverCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			discoverCount.Add(1)

			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      "http://" + r.Host + "/ocm",
				Capabilities:  []string{"exchange-token", "http-sig"},
				TokenEndPoint: "http://" + r.Host + "/ocm/token",
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

			return
		}

		if r.URL.Path == "/ocm/token" {
			if r.Header.Get("Signature") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"` + exchangedToken + `","token_type":"Bearer","expires_in":3600}`)) //nolint:errcheck // test mock handler: response write

			return
		}

		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			if r.Header.Get("Authorization") == "Bearer "+exchangedToken {
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
			SharedSecret: "secret",
			WebDAVID:     "file-123",
			Requirements: []string{spec.RequirementMustExchangeToken},
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

	if got := discoverCount.Load(); got != 1 {
		t.Errorf("discovery count = %d, want 1 (prefetch avoids second discover)", got)
	}
}
