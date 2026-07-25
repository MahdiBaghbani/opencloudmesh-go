package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

func TestAccess_WebappDoesNotUseWebDAVSharedSecret(t *testing.T) {
	var webdavHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exchangeDiscoveryHandler(w, r, "exchanged-token") {
			return
		}
		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			webdavHits.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client, _ := newExchangeAccessClient(t, srv)
	// Empty target intersection forces a fail-closed decision before any WebDAV request.
	client.SetWebappReceiveTargets([]string{"blank"})

	_, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:            "accepted",
			SenderHost:        srv.URL,
			SharedSecret:      "secret",
			WebDAVID:          "file-id",
			ProtocolName:      "webapp",
			Requirements:      []string{spec.RequirementMustExchangeToken},
			WebappURI:         "http://" + srv.Listener.Addr().String() + "/webapp",
			WebappTargets:     []string{"files"},
			WebappPermissions: []string{"read"},
		},
		Protocol: "webapp",
		Method:   "GET",
	})
	if err == nil {
		t.Fatal("expected webapp branch to fail closed in this layer")
	}
	if got := webdavHits.Load(); got != 0 {
		t.Errorf("webdav hits = %d, want 0 (webapp must not use WebDAV shared-secret browser path)", got)
	}
}

func TestAccess_WebappCodeFlowSuccess(t *testing.T) {
	const exchangedToken = "exchanged-webapp-token"
	const sharedSecret = "my-shared-secret"
	var formHits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exchangeDiscoveryHandler(w, r, exchangedToken) {
			return
		}
		if r.URL.Path == "/webapp" {
			formHits.Add(1)
			if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
			}
			_ = r.ParseForm()
			if got := r.FormValue("access_token"); got != exchangedToken {
				t.Errorf("access_token = %q, want %q", got, exchangedToken)
			}
			if got := r.FormValue("expired_session_redirect_uri"); got == "" {
				t.Errorf("expired_session_redirect_uri is empty")
			}
			if got := r.FormValue("sharedSecret"); got != "" {
				t.Errorf("sharedSecret field must not be present in form body, got %q", got)
			}
			if strings.Contains(r.Form.Encode(), sharedSecret) {
				t.Errorf("form body must not contain shared secret")
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client, _ := newExchangeAccessClient(t, srv)
	client.SetLocalIdentity(localidentity.Identity{
		Origin:       "http://local.example.com",
		EndpointBase: "http://local.example.com",
	})
	client.SetWebappReceiveTargets([]string{"files"})

	result, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:        "accepted",
			SenderHost:    srv.URL,
			SharedSecret:  sharedSecret,
			Requirements:  []string{spec.RequirementMustExchangeToken},
			WebappURI:     srv.URL + "/webapp",
			WebappTargets: []string{"files"},
		},
		Protocol: "webapp",
		Method:   http.MethodPost,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer result.Response.Body.Close()

	if result.Response.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", result.Response.StatusCode, http.StatusOK)
	}
	if result.AccessToken != exchangedToken {
		t.Errorf("AccessToken = %q, want %q", result.AccessToken, exchangedToken)
	}
	if got := formHits.Load(); got != 1 {
		t.Errorf("form hits = %d, want 1", got)
	}
}
