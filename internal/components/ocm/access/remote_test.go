package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func newTestDiscoveryServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := discovery.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   "https://" + r.Host + "/ocm",
				ResourceTypes: []discovery.ResourceType{
					{
						Name:       "file",
						ShareTypes: []string{"user"},
						Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
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
	cfg := tshttp.PermissiveConfig()
	cfg.InsecureSkipVerify = true
	rawClient := httpclient.New(cfg, nil)
	discClient := discovery.NewClient(rawClient, nil)
	ctxClient := httpclient.NewContextClient(rawClient)
	return discClient, ctxClient
}

type accessMockSigner struct{}

func (accessMockSigner) Sign(req *http.Request) error {
	req.Header.Set("Signature", "mock-signature")
	return nil
}

func newHTTPTestContract(t *testing.T) *peercompat.CompiledContract {
	t.Helper()
	contract, err := peercompat.NewCompiledContract(
		map[string]*peercompat.Profile{
			"http-test": {
				Name:      "http-test",
				AllowHTTP: true,
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "*", Profile: "http-test"},
		},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}
	return contract
}

func newExchangeAccessClient(
	t *testing.T,
	srv *httptest.Server,
) (*Client, *httpclient.ContextClient) {
	t.Helper()
	discClient, ctxClient := newTestClients(srv.URL)
	contract := newHTTPTestContract(t)
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "strict",
		PeerContract: contract,
	}
	tokenClient := tokenoutgoing.NewClient(
		ctxClient,
		discClient,
		accessMockSigner{},
		policy,
		"local.example.com",
	)
	client := NewClient(
		ctxClient,
		discClient,
		tokenClient,
		peerorigin.NewResolver(true),
	)
	return client, ctxClient
}

func exchangeDiscoveryHandler(w http.ResponseWriter, r *http.Request, accessToken string) bool {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	if r.URL.Path == "/.well-known/ocm" {
		disc := discovery.Discovery{
			Enabled:       true,
			APIVersion:    "1.4.0",
			EndPoint:      scheme + "://" + r.Host + "/ocm",
			Capabilities:  []string{"exchange-token"},
			TokenEndPoint: scheme + "://" + r.Host + "/ocm/token",
			ResourceTypes: []discovery.ResourceType{
				{
					Name:       "file",
					ShareTypes: []string{"user"},
					Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(disc)
		return true
	}
	if r.URL.Path == "/ocm/token" {
		if r.Header.Get("Signature") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + accessToken + `","token_type":"Bearer","expires_in":3600}`))
		return true
	}
	return false
}

func TestBuildWebDAVURL_AbsoluteURIMatchingHost(t *testing.T) {
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := NewClient(ctxClient, discClient, nil, peerorigin.NewResolver(true))

	share := &ShareInfo{
		Status:       "accepted",
		SenderHost:   "sender.example.com",
		SharedSecret: "secret",
		WebDAVID:     "https://sender.example.com/remote.php/webdav/file.txt",
	}
	got, err := client.buildWebDAVURL(context.Background(), share, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "https://sender.example.com/remote.php/webdav/file.txt"
	if got != want {
		t.Errorf("buildWebDAVURL() = %q, want %q", got, want)
	}
}

func TestBuildWebDAVURL_AbsoluteURIMismatchedHost(t *testing.T) {
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := NewClient(ctxClient, discClient, nil, peerorigin.NewResolver(true))
	senderHost := discServer.Listener.Addr().String()

	share := &ShareInfo{
		Status:       "accepted",
		SenderHost:   senderHost,
		SharedSecret: "secret",
		WebDAVID:     "https://evil.example.com/webdav/file.txt",
	}
	got, err := client.buildWebDAVURL(context.Background(), share, "")
	if err != nil {
		errStr := err.Error()
		if containsStr(errStr, "evil.example.com") {
			t.Errorf("expected fallthrough to discovery, but error references evil host: %s", errStr)
		}
		return
	}
	parsed, parseErr := url.Parse(got)
	if parseErr != nil {
		t.Fatalf("parse discovery-derived URL: %v", parseErr)
	}
	if parsed.Host == "evil.example.com" {
		t.Errorf("expected discovery-derived host, got evil host in URL: %s", got)
	}
	if parsed.Host != senderHost {
		t.Errorf("expected discovery server host in URL, got %q (full URL: %s)", parsed.Host, got)
	}
}

func TestBuildWebDAVURL_AbsoluteURIParseError(t *testing.T) {
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := NewClient(ctxClient, discClient, nil, peerorigin.NewResolver(true))
	senderHost := discServer.Listener.Addr().String()

	share := &ShareInfo{
		Status:       "accepted",
		SenderHost:   senderHost,
		SharedSecret: "secret",
		WebDAVID:     "://not-a-valid-url",
	}

	got, err := client.buildWebDAVURL(context.Background(), share, "")
	if err != nil {
		errStr := err.Error()
		if containsStr(errStr, "not-a-valid-url") {
			t.Errorf("expected fallthrough to discovery, but error references bad URI: %s", errStr)
		}
		return
	}
	parsed, parseErr := url.Parse(got)
	if parseErr != nil {
		t.Fatalf("parse discovery-derived URL: %v", parseErr)
	}
	if parsed.Host != senderHost {
		t.Errorf("expected discovery server host in URL, got %q (full URL: %s)", parsed.Host, got)
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

func TestAccess_AlwaysExchanges_BearerSucceeds(t *testing.T) {
	const exchangedToken = "exchanged-access-token"
	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exchangeDiscoveryHandler(w, r, exchangedToken) {
			return
		}
		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			requestCount.Add(1)
			if r.Header.Get("Authorization") == "Bearer "+exchangedToken {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("file content"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client, _ := newExchangeAccessClient(t, srv)

	result, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   srv.URL,
			SharedSecret: "my-shared-secret",
			WebDAVID:     "file-123",
		},
		Method:  "GET",
		SubPath: "doc.txt",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer result.Response.Body.Close()

	if result.Response.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", result.Response.StatusCode, http.StatusOK)
	}
	if got := requestCount.Load(); got != 1 {
		t.Errorf("request count = %d, want 1 (single Bearer attempt)", got)
	}
}

func TestAccess_ExchangeFailureFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := discovery.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   "http://" + r.Host + "/ocm",
				ResourceTypes: []discovery.ResourceType{
					{
						Name:       "file",
						ShareTypes: []string{"user"},
						Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client, _ := newExchangeAccessClient(t, srv)

	_, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   srv.URL,
			SharedSecret: "secret",
			WebDAVID:     "file-id",
		},
		Method: "GET",
	})
	if err == nil {
		t.Fatal("expected exchange failure, got nil")
	}
	if !strings.Contains(err.Error(), "exchange-token") {
		t.Errorf("expected capability-missing error, got: %v", err)
	}
}

func TestAccess_NilTokenClientFailsClosed(t *testing.T) {
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := NewClient(ctxClient, discClient, nil, peerorigin.NewResolver(true))

	_, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   discServer.URL,
			SharedSecret: "secret",
			WebDAVID:     "file-id",
		},
		Method: "GET",
	})
	if !errors.Is(err, ErrTokenExchangeRequired) {
		t.Errorf("expected ErrTokenExchangeRequired, got: %v", err)
	}
}

func TestAccess_Bearer401ReturnedAsIs(t *testing.T) {
	const exchangedToken = "exchanged-access-token"
	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exchangeDiscoveryHandler(w, r, exchangedToken) {
			return
		}
		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			requestCount.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client, _ := newExchangeAccessClient(t, srv)

	result, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   srv.URL,
			SharedSecret: "secret",
			WebDAVID:     "file-id",
		},
		Method: "GET",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer result.Response.Body.Close()

	if result.Response.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", result.Response.StatusCode, http.StatusUnauthorized)
	}
	if got := requestCount.Load(); got != 1 {
		t.Errorf("request count = %d, want 1 (no Basic retry)", got)
	}
}

func TestAccess_Bearer403ReturnedAsIs(t *testing.T) {
	const exchangedToken = "exchanged-access-token"
	var webdavRequestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exchangeDiscoveryHandler(w, r, exchangedToken) {
			return
		}
		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			webdavRequestCount.Add(1)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client, _ := newExchangeAccessClient(t, srv)

	result, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   srv.URL,
			SharedSecret: "secret",
			WebDAVID:     "file-id",
		},
		Method: "GET",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer result.Response.Body.Close()

	if result.Response.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want %d", result.Response.StatusCode, http.StatusForbidden)
	}
	if got := webdavRequestCount.Load(); got != 1 {
		t.Errorf("webdav request count = %d, want 1 (no credential retry)", got)
	}
}

func TestAccess_UsesOwnerHostForTokenExchangeProfile(t *testing.T) {
	var tokenGrantType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := discovery.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      "http://" + r.Host + "/ocm",
				Capabilities:  []string{"exchange-token"},
				TokenEndPoint: "http://" + r.Host + "/ocm/token",
				ResourceTypes: []discovery.ResourceType{
					{
						Name:       "file",
						ShareTypes: []string{"user"},
						Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
			return
		}
		if r.URL.Path == "/ocm/token" {
			if r.Header.Get("Signature") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = r.ParseForm()
			tokenGrantType = r.FormValue("grant_type")
			if tokenGrantType != "authorization_code" {
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
			AllowHTTP:              true,
			TokenExchangeGrantType: "ocm_share",
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: ownerDomain, Profile: "owner-grant"},
	}
	registry := peercompat.NewProfileRegistry(profiles, mappings)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "strict",
		PeerContract: contract,
	}
	tokenClient := tokenoutgoing.NewClient(ctxClient, discClient, accessMockSigner{}, policy, "local.example.com")
	client := NewClient(ctxClient, discClient, tokenClient, peerorigin.NewResolver(true))

	result, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   "sender.example.com",
			OwnerHost:    srv.URL,
			SharedSecret: "secret",
			WebDAVID:     "file-123",
		},
		Method: "GET",
	})
	if err != nil {
		t.Fatalf("unexpected access error: %v", err)
	}
	defer result.Response.Body.Close()

	if tokenGrantType != "authorization_code" {
		t.Fatalf("expected strict authorization_code grant_type, got %q", tokenGrantType)
	}
	if result.Response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", result.Response.StatusCode)
	}
}
