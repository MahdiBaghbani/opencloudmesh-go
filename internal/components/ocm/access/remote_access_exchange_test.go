package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

// unsignedMockSigner satisfies the signer interface without adding a Signature header.
type unsignedMockSigner struct{}

func (unsignedMockSigner) Sign(req *http.Request) error {
	return nil
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

	client := newExchangeAccessClient(t, srv)

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

	client := newExchangeAccessClient(t, srv)

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

	client := newExchangeAccessClient(t, srv)

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

	client := newExchangeAccessClient(t, srv)

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

	client := newExchangeAccessClient(t, srv)

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
