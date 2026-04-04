package access_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

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

	share := &access.ShareInfo{
		Status:            "accepted",
		SenderHost:        "sender.example.com",
		SharedSecret:      "secret",
		WebDAVID:          "relative-id",
		WebDAVURIAbsolute: "https://sender.example.com/remote.php/webdav/file.txt",
		MustExchangeToken: false,
	}
	_, err := client.Access(context.Background(), access.AccessOptions{
		Share:   share,
		Method:  "GET",
		SubPath: "",
	})
	if err == nil {
		t.Fatal("expected error (unreachable host), got nil")
	}
	errStr := err.Error()
	if !containsStr(errStr, "sender.example.com") {
		t.Errorf("expected error to reference sender.example.com, got: %s", errStr)
	}
}

func TestBuildWebDAVURL_AbsoluteURIMismatchedHost(t *testing.T) {
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := access.NewClient(ctxClient, discClient, nil, nil)

	share := &access.ShareInfo{
		Status:            "accepted",
		SenderHost:        discServer.Listener.Addr().String(),
		SharedSecret:      "secret",
		WebDAVID:          "file-id-123",
		WebDAVURIAbsolute: "https://evil.example.com/webdav/file.txt",
		MustExchangeToken: false,
	}
	_, err := client.Access(context.Background(), access.AccessOptions{
		Share:   share,
		Method:  "GET",
		SubPath: "",
	})
	if err != nil {
		errStr := err.Error()
		if containsStr(errStr, "evil.example.com") {
			t.Errorf("expected fallthrough to discovery, but error references evil host: %s", errStr)
		}
	}
}

func TestBuildWebDAVURL_AbsoluteURIParseError(t *testing.T) {
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
	if len(receivedAuths) != 2 {
		t.Errorf("received %d auth attempts, want 2 (Bearer + id:token); auths: %v", len(receivedAuths), receivedAuths)
	}
}

func TestAuthLadder_AllPatternsFail(t *testing.T) {
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
	if !errors.Is(err, access.ErrRemoteAccessFailed) {
		t.Errorf("error = %q, want wrapped ErrRemoteAccessFailed", err.Error())
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
	if !errors.Is(err, access.ErrRemoteAccessFailed) {
		t.Errorf("error = %q, want wrapped ErrRemoteAccessFailed", err.Error())
	}
	if got := requestCount.Load(); got != 1 {
		t.Errorf("request count = %d, want 1 (only Bearer)", got)
	}
}

func TestAuthLadder_ResponseBodiesClosed(t *testing.T) {
	var requestCount atomic.Int32
	srv := newAuthLadderServer(func(authHeader string) bool {
		requestCount.Add(1)
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
	if got := requestCount.Load(); got != 5 {
		t.Errorf("request count = %d, want 5 (Bearer + 4 Basic patterns)", got)
	}
}

func TestAccess_UsesOwnerHostForTokenExchangeProfile(t *testing.T) {
	var tokenGrantType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := discovery.Discovery{
				Enabled:       true,
				APIVersion:    "1.2.2",
				EndPoint:      "http://" + r.Host + "/ocm",
				Capabilities:  []string{"exchange-token"},
				TokenEndPoint: "http://" + r.Host + "/ocm/token",
				ResourceTypes: []discovery.ResourceType{
					{
						Name:       "file",
						ShareTypes: []string{"user"},
						Protocols:  map[string]string{"webdav": "/webdav/ocm"},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
			return
		}
		if r.URL.Path == "/ocm/token" {
			_ = r.ParseForm()
			tokenGrantType = r.FormValue("grant_type")
			if tokenGrantType != "ocm_share" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"wrong grant"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"owner-token","token_type":"Bearer","expires_in":3600}`))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			if r.Header.Get("Authorization") != "Bearer owner-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	discClient, ctxClient := newTestClients(srv.URL)
	ownerDomain := strings.Split(srv.Listener.Addr().String(), ":")[0]
	profiles := map[string]*peercompat.Profile{
		"owner-grant": {
			Name:                   "owner-grant",
			TokenExchangeGrantType: "ocm_share",
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: ownerDomain, ProfileName: "owner-grant"},
	}
	registry := peercompat.NewProfileRegistry(profiles, mappings)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode:        "off",
		PeerProfileOverride: "non-strict",
		PeerContract:        contract,
	}
	tokenClient := tokenoutgoing.NewClient(ctxClient, discClient, nil, policy, "local.example.com")
	client := access.NewClient(ctxClient, discClient, tokenClient, registry)

	result, err := client.Access(context.Background(), access.AccessOptions{
		Share: &access.ShareInfo{
			Status:            "accepted",
			SenderHost:        "sender.example.com",
			OwnerHost:         srv.URL,
			SharedSecret:      "secret",
			WebDAVID:          "file-123",
			MustExchangeToken: true,
		},
		Method: "GET",
	})
	if err != nil {
		t.Fatalf("unexpected access error: %v", err)
	}
	defer result.Response.Body.Close()

	if tokenGrantType != "ocm_share" {
		t.Fatalf("expected owner profile grant_type ocm_share, got %q", tokenGrantType)
	}
	if result.Response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", result.Response.StatusCode)
	}
}

func TestAccess_UsesOwnerHostProfileForBasicFallback(t *testing.T) {
	token := "my-shared-secret"
	webdavID := "file-owner-basic-1"
	ownerAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(webdavID+":"+token))

	var receivedAuths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			auth := r.Header.Get("Authorization")
			receivedAuths = append(receivedAuths, auth)
			if auth == ownerAuth {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	discClient, ctxClient := newTestClients(srv.URL)

	ownerHost := srv.Listener.Addr().String()
	ownerDomain := strings.Split(ownerHost, ":")[0]
	customProfiles := map[string]*peercompat.Profile{
		"owner-only-id-token": {
			Name:                     "owner-only-id-token",
			AllowedBasicAuthPatterns: []string{"id:token"},
		},
		"sender-only-token-colon": {
			Name:                     "sender-only-token-colon",
			AllowedBasicAuthPatterns: []string{"token:"},
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: ownerDomain, ProfileName: "owner-only-id-token"},
		{Pattern: "sender.example.com", ProfileName: "sender-only-token-colon"},
	}
	registry := peercompat.NewProfileRegistry(customProfiles, mappings)

	client := access.NewClient(ctxClient, discClient, nil, registry)
	result, err := client.Access(context.Background(), access.AccessOptions{
		Share: &access.ShareInfo{
			Status:            "accepted",
			SenderHost:        "sender.example.com",
			OwnerHost:         ownerHost,
			SharedSecret:      token,
			WebDAVID:          webdavID,
			WebDAVURIAbsolute: "http://" + ownerHost + "/webdav/ocm/" + webdavID + "/doc.txt",
		},
		Method: "GET",
	})
	if err != nil {
		t.Fatalf("unexpected access error: %v", err)
	}
	defer result.Response.Body.Close()

	if result.MethodUsed != "basic:id:token" {
		t.Fatalf("expected owner-profile basic:id:token fallback, got %q", result.MethodUsed)
	}
	if result.Response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", result.Response.StatusCode)
	}
	if len(receivedAuths) != 2 {
		t.Fatalf("expected 2 auth attempts (Bearer, id:token), got %d: %v", len(receivedAuths), receivedAuths)
	}
}
