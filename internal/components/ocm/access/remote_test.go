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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// unsignedMockSigner satisfies the signer interface without adding a Signature header.
// It is used to exercise the unsigned 401 fail-closed path.
type unsignedMockSigner struct{}

func (unsignedMockSigner) Sign(req *http.Request) error {
	return nil
}

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
	_ = json.NewEncoder(w).Encode(disc)
	return true
}

func TestBuildWebDAVURL_AbsoluteURIMatchingHost(t *testing.T) {
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := NewClient(ctxClient, discClient, nil, peerorigin.NewResolver(true))
	disc, err := discClient.Discover(context.Background(), discServer.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	share := &ShareInfo{
		Status:       "accepted",
		SenderHost:   "sender.example.com",
		SharedSecret: "secret",
		WebDAVID:     "https://sender.example.com/remote.php/webdav/file.txt",
	}
	got, err := client.buildWebDAVURL(context.Background(), share, "", disc)
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
	disc, err := discClient.Discover(context.Background(), discServer.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	share := &ShareInfo{
		Status:       "accepted",
		SenderHost:   senderHost,
		SharedSecret: "secret",
		WebDAVID:     "https://evil.example.com/webdav/file.txt",
	}
	got, err := client.buildWebDAVURL(context.Background(), share, "", disc)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "evil.example.com") {
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
	disc, err := discClient.Discover(context.Background(), discServer.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	share := &ShareInfo{
		Status:       "accepted",
		SenderHost:   senderHost,
		SharedSecret: "secret",
		WebDAVID:     "://not-a-valid-url",
	}

	got, err := client.buildWebDAVURL(context.Background(), share, "", disc)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "not-a-valid-url") {
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
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
		Method:   "GET",
		SubPath:  "doc.txt",
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
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
		Method:   "GET",
	})
	if err == nil {
		t.Fatal("expected exchange failure, got nil")
	}
	if reason.ClassifyError(err) != reason.ReasonPeerCapabilityMissing {
		t.Errorf("expected reason %q, got %q", reason.ReasonPeerCapabilityMissing, reason.ClassifyError(err))
	}
}

func TestAccess_NilTokenClientFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exchangeDiscoveryHandler(w, r, "unused") {
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	discClient, ctxClient := newTestClients(srv.URL)
	client := NewClient(ctxClient, discClient, nil, peerorigin.NewResolver(true))

	_, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   srv.URL,
			SharedSecret: "secret",
			WebDAVID:     "file-id",
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
		Method:   "GET",
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
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
		Method:   "GET",
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
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
		Method:   "GET",
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
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      "http://" + r.Host + "/ocm",
				Capabilities:  []string{"exchange-token"},
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
	tokenClient := tokenoutgoing.NewClient(ctxClient, accessMockSigner{}, "local.example.com")
	client := NewClient(ctxClient, discClient, tokenClient, peerorigin.NewResolver(true))

	result, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   "sender.example.com",
			OwnerHost:    srv.URL,
			SharedSecret: "secret",
			WebDAVID:     "file-123",
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
		Method:   "GET",
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
				Capabilities:  []string{"exchange-token"},
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
			_ = json.NewEncoder(w).Encode(disc)
			return
		}
		if r.URL.Path == "/ocm/token" {
			if r.Header.Get("Signature") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"` + exchangedToken + `","token_type":"Bearer","expires_in":3600}`))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
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
	defer result.Response.Body.Close()

	if result.Response.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", result.Response.StatusCode, http.StatusOK)
	}
	if got := discoverCount.Load(); got != 1 {
		t.Errorf("discovery count = %d, want 1 (prefetch avoids second discover)", got)
	}
}

func TestAccess_UnsetProtocolFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exchangeDiscoveryHandler(w, r, "token") {
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
		t.Fatal("expected unset protocol to fail closed")
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch error, got: %v", err)
	}
}

func TestAccess_NilDiscoveryFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	client, _ := newExchangeAccessClient(t, srv)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   "http://example.com",
			SharedSecret: "secret",
			WebDAVID:     "file-id",
		},
		Protocol: "webdav",
		Method:   "GET",
	}, nil)
	if err == nil {
		t.Fatalf("expected nil discovery to fail closed, got mode %q", decision.Mode)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonDiscoveryFailed {
		t.Errorf("expected discovery failed error, got: %v", err)
	}
}

func TestAccess_TokenExchange401FailsClosed(t *testing.T) {
	var tokenHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      "http://" + r.Host + "/ocm",
				Capabilities:  []string{"exchange-token"},
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
			_ = json.NewEncoder(w).Encode(disc)
			return
		}
		if r.URL.Path == "/ocm/token" {
			tokenHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"client authentication failed"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	discClient, ctxClient := newTestClients(srv.URL)
	// Unsigned signer so the token client classifies the 401 as token_unauthorized.
	tokenClient := tokenoutgoing.NewClient(ctxClient, unsignedMockSigner{}, "local.example.com")
	client := NewClient(ctxClient, discClient, tokenClient, peerorigin.NewResolver(true))

	_, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   srv.URL,
			SharedSecret: "secret",
			WebDAVID:     "file-id",
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
		Method:   "GET",
	})
	if err == nil {
		t.Fatal("expected 401 token exchange to fail closed")
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonTokenUnauthorized {
		t.Errorf("expected reason %q, got %q: %v", reason.ReasonTokenUnauthorized, ce.ReasonCode, err)
	}
	if got := tokenHits.Load(); got != 1 {
		t.Errorf("token hits = %d, want 1 (no retry)", got)
	}
}

func TestAccess_TokenExchange403FailsClosed(t *testing.T) {
	var tokenHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      "http://" + r.Host + "/ocm",
				Capabilities:  []string{"exchange-token"},
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
			_ = json.NewEncoder(w).Encode(disc)
			return
		}
		if r.URL.Path == "/ocm/token" {
			tokenHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"access_denied","error_description":"token exchange denied"}`))
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
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
		Method:   "GET",
	})
	if err == nil {
		t.Fatal("expected 403 token exchange to fail closed")
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonTokenForbidden {
		t.Errorf("expected reason %q, got %q: %v", reason.ReasonTokenForbidden, ce.ReasonCode, err)
	}
	if got := tokenHits.Load(); got != 1 {
		t.Errorf("token hits = %d, want 1 (no retry)", got)
	}
}

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
			SharedSecret: "shared-secret",
			WebDAVID:     "file-123",
		},
		Protocol: "webdav",
		Method:   "GET",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer result.Response.Body.Close()

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

func TestDecideAccessAuth_WebDAVTokenExchange(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
	}, disc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Mode != AccessModeTokenExchange {
		t.Errorf("mode = %q, want %q", decision.Mode, AccessModeTokenExchange)
	}
}

func TestDecideAccessAuth_WebDAVSharedSecret(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:    true,
		APIVersion: "1.4.0",
		EndPoint:   "http://example.com/ocm",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share:    &ShareInfo{},
		Protocol: "webdav",
	}, disc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Mode != AccessModeSharedSecret {
		t.Errorf("mode = %q, want %q", decision.Mode, AccessModeSharedSecret)
	}
}

func TestDecideAccessAuth_WebDAVRequiresButNotCapable(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:    true,
		APIVersion: "1.4.0",
		EndPoint:   "http://example.com/ocm",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	_, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
	}, disc)
	if err == nil {
		t.Fatal("expected fail-closed when token exchange required but peer not capable")
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonPeerCapabilityMissing {
		t.Errorf("expected peer capability missing, got: %v", err)
	}
}

func TestDecideAccessAuth_WebDAVRequiresHTTPSigButNotCapable(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
		Criteria:      []string{spec.CriteriaMustUseHTTPSig},
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
	}, disc)
	if err == nil {
		t.Fatalf("expected fail-closed when peer requires http-sig but is not capable, got mode %q", decision.Mode)
	}
	if decision.Mode != AccessModeFailClosed {
		t.Errorf("mode = %q, want %q", decision.Mode, AccessModeFailClosed)
	}
	if decision.HTTPStatus != http.StatusForbidden {
		t.Errorf("HTTPStatus = %d, want %d", decision.HTTPStatus, http.StatusForbidden)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonSignatureRequired {
		t.Errorf("expected signature required, got: %v", err)
	}
}

// SharedSecret bearer access is unsigned per the OCM spec; must-use-http-sig
// governs OCM API requests such as the token POST, not bearer WebDAV resource
// access; therefore this branch does not fail closed on signature policy.
func TestDecideAccessAuth_WebDAVSharedSecret_IgnoresMustUseHTTPSig(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []string
	}{
		{
			name:         "advertises http-sig and capable",
			capabilities: []string{"http-sig"},
		},
		{
			name:         "advertises must-use-http-sig but not capable",
			capabilities: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			disc := &spec.Discovery{
				Enabled:      true,
				APIVersion:   "1.4.0",
				EndPoint:     "http://example.com/ocm",
				Capabilities: tt.capabilities,
				Criteria:     []string{spec.CriteriaMustUseHTTPSig},
			}
			client := NewClient(nil, &discovery.Client{}, nil, nil)

			decision, err := client.DecideAccessAuth(AccessOptions{
				Share:    &ShareInfo{},
				Protocol: "webdav",
			}, disc)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Mode != AccessModeSharedSecret {
				t.Errorf("mode = %q, want %q", decision.Mode, AccessModeSharedSecret)
			}
			if decision.HTTPStatus != http.StatusOK {
				t.Errorf("HTTPStatus = %d, want %d", decision.HTTPStatus, http.StatusOK)
			}
		})
	}
}

func TestAccess_NilShareFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exchangeDiscoveryHandler(w, r, "token") {
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client, _ := newExchangeAccessClient(t, srv)

	_, err := client.Access(context.Background(), AccessOptions{
		Share:    nil,
		Protocol: "webdav",
		Method:   "GET",
	})
	if err == nil {
		t.Fatal("expected nil share to fail closed")
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch error, got: %v", err)
	}
}

func TestDecideAccessAuth_NilShareFailsClosed(t *testing.T) {
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share:    nil,
		Protocol: "webdav",
	}, &spec.Discovery{})
	if err == nil {
		t.Fatalf("expected nil share to fail closed, got mode %q", decision.Mode)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch error, got: %v", err)
	}
}

func TestDecideAccessAuth_WebappMissingFieldsFailsClosed(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webapp",
	}, disc)
	if err == nil {
		t.Fatalf("expected fail-closed for missing webapp fields, got mode %q", decision.Mode)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch, got: %v", err)
	}
}

func TestDecideAccessAuth_WebappMissingRequirementFailsClosed(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			WebappURI:     "http://example.com/webapp",
			WebappTargets: []string{"files"},
			SharedSecret:  "secret",
		},
		Protocol: "webapp",
	}, disc)
	if err == nil {
		t.Fatalf("expected fail-closed for missing must-exchange-token, got mode %q", decision.Mode)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch, got: %v", err)
	}
}

func TestDecideAccessAuth_WebappMissingTargetIntersectionFailsClosed(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)
	client.SetWebappReceiveTargets([]string{"blank"})

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements:  []string{spec.RequirementMustExchangeToken},
			WebappURI:     "http://example.com/webapp",
			WebappTargets: []string{"files"},
			SharedSecret:  "secret",
		},
		Protocol: "webapp",
	}, disc)
	if err == nil {
		t.Fatalf("expected fail-closed for empty target intersection, got mode %q", decision.Mode)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch, got: %v", err)
	}
}

func TestDecideAccessAuth_WebappNoLocalTargetsFailsClosed(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)
	// No local webapp receive targets configured.

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements:  []string{spec.RequirementMustExchangeToken},
			WebappURI:     "http://example.com/webapp",
			WebappTargets: []string{"files"},
			SharedSecret:  "secret",
		},
		Protocol: "webapp",
	}, disc)
	if err == nil {
		t.Fatalf("expected fail-closed when no local webapp targets are configured, got mode %q", decision.Mode)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch, got: %v", err)
	}
}

func TestDecideAccessAuth_WebappRequiresHTTPSigButNotCapable(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
		Criteria:      []string{spec.CriteriaMustUseHTTPSig},
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements:      []string{spec.RequirementMustExchangeToken},
			WebappURI:         "http://example.com/webapp",
			WebappTargets:     []string{"files"},
			WebappPermissions: []string{"read"},
			SharedSecret:      "secret",
		},
		Protocol: "webapp",
	}, disc)
	if err == nil {
		t.Fatalf("expected fail-closed when peer requires http-sig but is not capable, got mode %q", decision.Mode)
	}
	if decision.Mode != AccessModeFailClosed {
		t.Errorf("mode = %q, want %q", decision.Mode, AccessModeFailClosed)
	}
	if decision.HTTPStatus != http.StatusForbidden {
		t.Errorf("HTTPStatus = %d, want %d", decision.HTTPStatus, http.StatusForbidden)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonSignatureRequired {
		t.Errorf("expected signature required, got: %v", err)
	}
}

func TestDecideAccessAuth_WebappCodeFlowSuccess(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)
	client.SetWebappReceiveTargets([]string{"files"})

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements:  []string{spec.RequirementMustExchangeToken},
			WebappURI:     "http://example.com/webapp",
			WebappTargets: []string{"files"},
			SharedSecret:  "secret",
		},
		Protocol: "webapp",
	}, disc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Mode != AccessModeWebappCodeFlow {
		t.Errorf("mode = %q, want %q", decision.Mode, AccessModeWebappCodeFlow)
	}
	if decision.HTTPStatus != http.StatusOK {
		t.Errorf("HTTPStatus = %d, want %d", decision.HTTPStatus, http.StatusOK)
	}
}
