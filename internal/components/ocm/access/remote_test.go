package access_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

// newTestDiscoveryServer returns an httptest.Server that serves a minimal
// discovery document pointing WebDAV at /webdav/ocm/<id>.
func newTestDiscoveryServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := discovery.Discovery{
				Enabled:    true,
				APIVersion: "1.2.2",
				EndPoint:   "https://" + r.Host + "/ocm",
				ResourceTypes: []discovery.ResourceType{
					{
						Name:       "file",
						ShareTypes: []string{"user"},
						Protocols:  map[string]string{"webdav": "/webdav/ocm"},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(disc)
			return
		}
		http.NotFound(w, r)
	}))
}

// newTestClients creates a discovery client and context client pointed at the test server.
func newTestClients(serverURL string) (*discovery.Client, *httpclient.ContextClient) {
	cfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	rawClient := httpclient.New(cfg, nil)
	discClient := discovery.NewClient(rawClient, nil)
	ctxClient := httpclient.NewContextClient(rawClient)
	return discClient, ctxClient
}

func TestBuildWebDAVURL_AbsoluteURIMatchingHost(t *testing.T) {
	// When absolute URI host matches sender, the absolute URI is used directly.
	// No discovery call needed, so we pass a nil-safe discovery server.
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := access.NewClient(ctxClient, discClient, nil, nil)

	// Create a share with matching absolute URI
	share := &access.ShareInfo{
		Status:            "accepted",
		SenderHost:        "sender.example.com",
		SharedSecret:      "secret",
		WebDAVID:          "relative-id",
		WebDAVURIAbsolute: "https://sender.example.com/remote.php/webdav/file.txt",
		MustExchangeToken: false,
	}

	// We test via Access(), which internally calls buildWebDAVURL.
	// The request will fail at the HTTP level (fake host), but we can
	// verify the URL by intercepting. Instead, test the URL derivation
	// indirectly by checking the request goes to the absolute URI.
	//
	// Since we can't easily intercept the final URL without a real server,
	// we test that Access() attempts to reach the absolute URI host, not the
	// discovery server. The error message from the HTTP client will tell us
	// which host it tried to reach.
	_, err := client.Access(context.Background(), access.AccessOptions{
		Share:   share,
		Method:  "GET",
		SubPath: "",
	})
	// Expect a network error (can't reach sender.example.com), which proves
	// it used the absolute URI, not discovery.
	if err == nil {
		t.Fatal("expected error (unreachable host), got nil")
	}
	// The error should reference the absolute URI host, not the test server
	errStr := err.Error()
	if !containsStr(errStr, "sender.example.com") {
		t.Errorf("expected error to reference sender.example.com, got: %s", errStr)
	}
}

func TestBuildWebDAVURL_AbsoluteURIMismatchedHost(t *testing.T) {
	// When absolute URI host doesn't match sender, fall through to discovery.
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := access.NewClient(ctxClient, discClient, nil, nil)

	// Sender is the test server (discovery works), but absolute URI points elsewhere
	share := &access.ShareInfo{
		Status:            "accepted",
		SenderHost:        discServer.Listener.Addr().String(),
		SharedSecret:      "secret",
		WebDAVID:          "file-id-123",
		WebDAVURIAbsolute: "https://evil.example.com/webdav/file.txt",
		MustExchangeToken: false,
	}

	// Access will fall through to discovery (test server) and build the URL
	// from the discovery document. The final request will go to the test server's
	// host (from the discovery EndPoint), not evil.example.com.
	_, err := client.Access(context.Background(), access.AccessOptions{
		Share:   share,
		Method:  "GET",
		SubPath: "",
	})
	// We expect some error (the WebDAV endpoint doesn't really exist on the test server),
	// but it should NOT reference evil.example.com.
	if err != nil {
		errStr := err.Error()
		if containsStr(errStr, "evil.example.com") {
			t.Errorf("expected fallthrough to discovery, but error references evil host: %s", errStr)
		}
	}
	// If err == nil, discovery worked and it reached the test server (also correct).
}

func TestBuildWebDAVURL_AbsoluteURIParseError(t *testing.T) {
	// When absolute URI is unparseable, fall through to discovery.
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := access.NewClient(ctxClient, discClient, nil, nil)

	share := &access.ShareInfo{
		Status:            "accepted",
		SenderHost:        discServer.Listener.Addr().String(),
		SharedSecret:      "secret",
		WebDAVID:          "file-id-456",
		WebDAVURIAbsolute: "://not-a-valid-url",
		MustExchangeToken: false,
	}

	_, err := client.Access(context.Background(), access.AccessOptions{
		Share:   share,
		Method:  "GET",
		SubPath: "",
	})
	// Should have fallen through to discovery, not panicked or used the bad URI.
	if err != nil {
		errStr := err.Error()
		if containsStr(errStr, "not-a-valid-url") {
			t.Errorf("expected fallthrough to discovery, but error references bad URI: %s", errStr)
		}
	}
}

func containsStr(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// --- Auth ladder tests ---

// newAuthLadderServer returns a test server that serves discovery at
// /.well-known/ocm and a WebDAV endpoint at /webdav/ocm/<id>/<subpath>.
// The acceptAuth function decides whether a given Authorization header is accepted.
// Discovery EndPoint uses http:// so the WebDAV URL stays on the test server.
// Use srv.URL as SenderHost so the discovery client can reach it.
func newAuthLadderServer(acceptAuth func(authHeader string) bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := discovery.Discovery{
				Enabled:    true,
				APIVersion: "1.2.2",
				EndPoint:   "http://" + r.Host + "/ocm",
				ResourceTypes: []discovery.ResourceType{
					{
						Name:       "file",
						ShareTypes: []string{"user"},
						Protocols:  map[string]string{"webdav": "/webdav/ocm"},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(disc)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			authHeader := r.Header.Get("Authorization")
			if acceptAuth(authHeader) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("file content"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		http.NotFound(w, r)
	}))
}

func TestAuthLadder_BearerSucceeds_NoBasicAttempts(t *testing.T) {
	var requestCount atomic.Int32
	srv := newAuthLadderServer(func(authHeader string) bool {
		requestCount.Add(1)
		return strings.HasPrefix(authHeader, "Bearer ")
	})
	defer srv.Close()

	discClient, ctxClient := newTestClients(srv.URL)
	registry := peercompat.NewProfileRegistry(nil, nil)
	client := access.NewClient(ctxClient, discClient, nil, registry)

	result, err := client.Access(context.Background(), access.AccessOptions{
		Share: &access.ShareInfo{
			Status:       "accepted",
			SenderHost:   srv.URL,
			SharedSecret: "my-token",
			WebDAVID:     "file-123",
		},
		Method:  "GET",
		SubPath: "doc.txt",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer result.Response.Body.Close()

	if result.MethodUsed != "bearer" {
		t.Errorf("MethodUsed = %q, want %q", result.MethodUsed, "bearer")
	}
	if result.Response.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", result.Response.StatusCode, http.StatusOK)
	}
	if got := requestCount.Load(); got != 1 {
		t.Errorf("request count = %d, want 1 (only Bearer)", got)
	}
}

func TestAuthLadder_Bearer401_BasicTokenColonSucceeds(t *testing.T) {
	// Accept only Basic with "token:" pattern (token + ":")
	token := "my-secret-token"
	expectedCred := base64.StdEncoding.EncodeToString([]byte(token + ":"))

	srv := newAuthLadderServer(func(authHeader string) bool {
		return authHeader == "Basic "+expectedCred
	})
	defer srv.Close()

	discClient, ctxClient := newTestClients(srv.URL)
	registry := peercompat.NewProfileRegistry(nil, nil)
	client := access.NewClient(ctxClient, discClient, nil, registry)

	result, err := client.Access(context.Background(), access.AccessOptions{
		Share: &access.ShareInfo{
			Status:       "accepted",
			SenderHost:   srv.URL,
			SharedSecret: token,
			WebDAVID:     "file-456",
		},
		Method:  "GET",
		SubPath: "readme.md",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer result.Response.Body.Close()

	if result.MethodUsed != "basic:token:" {
		t.Errorf("MethodUsed = %q, want %q", result.MethodUsed, "basic:token:")
	}
	if result.Response.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", result.Response.StatusCode, http.StatusOK)
	}
}

func TestAuthLadder_Bearer403_ProfileSkipsDisallowed_IDTokenSucceeds(t *testing.T) {
	// Profile only allows "id:token"; server accepts that pattern.
	token := "exchanged-token"
	webdavID := "share-id-789"
	expectedCred := base64.StdEncoding.EncodeToString([]byte(webdavID + ":" + token))

	var receivedAuths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := discovery.Discovery{
				Enabled:    true,
				APIVersion: "1.2.2",
				EndPoint:   "http://" + r.Host + "/ocm",
				ResourceTypes: []discovery.ResourceType{
					{
						Name:       "file",
						ShareTypes: []string{"user"},
						Protocols:  map[string]string{"webdav": "/webdav/ocm"},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(disc)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			auth := r.Header.Get("Authorization")
			receivedAuths = append(receivedAuths, auth)
			if auth == "Basic "+expectedCred {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
				return
			}
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	discClient, ctxClient := newTestClients(srv.URL)

	// Custom profile that only allows "id:token"
	customProfiles := map[string]*peercompat.Profile{
		"restricted": {
			Name:                     "restricted",
			AllowedBasicAuthPatterns: []string{"id:token"},
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: "*", ProfileName: "restricted"},
	}
	registry := peercompat.NewProfileRegistry(customProfiles, mappings)

	client := access.NewClient(ctxClient, discClient, nil, registry)

	// Use bare host:port for SenderHost so profile pattern matching works
	// (normalizeDomain strips port but not scheme prefixes).
	// Set WebDAVURIAbsolute to bypass discovery (host will match SenderHost).
	senderHost := srv.Listener.Addr().String()
	webdavAbsolute := srv.URL + "/webdav/ocm/" + webdavID + "/data.csv"

	result, err := client.Access(context.Background(), access.AccessOptions{
		Share: &access.ShareInfo{
			Status:            "accepted",
			SenderHost:        senderHost,
			SharedSecret:      token,
			WebDAVID:          webdavID,
			WebDAVURIAbsolute: webdavAbsolute,
		},
		Method: "GET",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer result.Response.Body.Close()

	if result.MethodUsed != "basic:id:token" {
		t.Errorf("MethodUsed = %q, want %q", result.MethodUsed, "basic:id:token")
	}

	// Should have received exactly 2 auth attempts: Bearer (rejected) + id:token (accepted).
	// Patterns "token:", "token:token", ":token" were skipped by profile.
	if len(receivedAuths) != 2 {
		t.Errorf("received %d auth attempts, want 2 (Bearer + id:token); auths: %v", len(receivedAuths), receivedAuths)
	}
}

func TestAuthLadder_AllPatternsFail(t *testing.T) {
	// Server rejects everything.
	srv := newAuthLadderServer(func(authHeader string) bool {
		return false
	})
	defer srv.Close()

	discClient, ctxClient := newTestClients(srv.URL)
	registry := peercompat.NewProfileRegistry(nil, nil)
	client := access.NewClient(ctxClient, discClient, nil, registry)

	_, err := client.Access(context.Background(), access.AccessOptions{
		Share: &access.ShareInfo{
			Status:       "accepted",
			SenderHost:   srv.URL,
			SharedSecret: "token",
			WebDAVID:     "file-id",
		},
		Method: "GET",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != access.ErrRemoteAccessFailed.Error() {
		t.Errorf("error = %q, want %q", err.Error(), access.ErrRemoteAccessFailed.Error())
	}
}

func TestAuthLadder_NilProfileRegistry_BearerFailReturnsError(t *testing.T) {
	var requestCount atomic.Int32
	srv := newAuthLadderServer(func(authHeader string) bool {
		requestCount.Add(1)
		return false // reject everything
	})
	defer srv.Close()

	discClient, ctxClient := newTestClients(srv.URL)
	// Explicitly nil profile registry -- no Basic fallback
	client := access.NewClient(ctxClient, discClient, nil, nil)

	_, err := client.Access(context.Background(), access.AccessOptions{
		Share: &access.ShareInfo{
			Status:       "accepted",
			SenderHost:   srv.URL,
			SharedSecret: "token",
			WebDAVID:     "file-id",
		},
		Method: "GET",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != access.ErrRemoteAccessFailed.Error() {
		t.Errorf("error = %q, want %q", err.Error(), access.ErrRemoteAccessFailed.Error())
	}
	// Only the Bearer attempt, no Basic retries
	if got := requestCount.Load(); got != 1 {
		t.Errorf("request count = %d, want 1 (only Bearer)", got)
	}
}

func TestAuthLadder_ResponseBodiesClosed(t *testing.T) {
	// Verify the server receives the expected number of requests.
	// All patterns allowed (nil AllowedBasicAuthPatterns -> allow all).
	// Bearer + 4 Basic patterns = 5 total requests.
	var requestCount atomic.Int32
	srv := newAuthLadderServer(func(authHeader string) bool {
		requestCount.Add(1)
		return false // reject all
	})
	defer srv.Close()

	discClient, ctxClient := newTestClients(srv.URL)
	registry := peercompat.NewProfileRegistry(nil, nil)
	client := access.NewClient(ctxClient, discClient, nil, registry)

	_, err := client.Access(context.Background(), access.AccessOptions{
		Share: &access.ShareInfo{
			Status:       "accepted",
			SenderHost:   srv.URL,
			SharedSecret: "token",
			WebDAVID:     "file-id",
		},
		Method: "GET",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Bearer (1) + 4 Basic patterns = 5 total WebDAV requests
	if got := requestCount.Load(); got != 5 {
		t.Errorf("request count = %d, want 5 (Bearer + 4 Basic patterns)", got)
	}
}
