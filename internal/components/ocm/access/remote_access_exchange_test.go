// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package access

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

// unsignedMockSigner satisfies the signer interface without adding a Signature header.
type unsignedMockSigner struct{}

func (unsignedMockSigner) Sign(_ *http.Request) error {
	return nil
}

func TestAccess_AlwaysExchanges_BearerSucceeds(t *testing.T) {
	t.Parallel()

	const exchangedToken = "exchanged-access-token"

	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exchangeDiscoveryHandler(t, w, r, exchangedToken) {
			return
		}

		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			requestCount.Add(1)

			if r.Header.Get("Authorization") == "Bearer "+exchangedToken {
				w.WriteHeader(http.StatusOK)
				tshttp.MustWrite(t, w, []byte("file content"))

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
	defer tshttp.MustClose(t, result.Response.Body)

	if result.Response.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", result.Response.StatusCode, http.StatusOK)
	}

	if got := requestCount.Load(); got != 1 {
		t.Errorf("request count = %d, want 1 (single Bearer attempt)", got)
	}
}

func TestAccess_ExchangeFailureFailsClosed(t *testing.T) {
	t.Parallel()

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
			tshttp.WriteJSON(w, disc)

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
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exchangeDiscoveryHandler(t, w, r, "unused") {
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

// assertBearerStatusReturnedAsIs drives one bearer-failure passthrough case:
// the WebDAV endpoint fails with wantStatus after token exchange and the
// client must surface that status without retrying other credentials.
func assertBearerStatusReturnedAsIs(t *testing.T, wantStatus int) {
	t.Helper()

	const exchangedToken = "exchanged-access-token"

	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exchangeDiscoveryHandler(t, w, r, exchangedToken) {
			return
		}

		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			requestCount.Add(1)
			w.WriteHeader(wantStatus)

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
	defer tshttp.MustClose(t, result.Response.Body)

	if result.Response.StatusCode != wantStatus {
		t.Errorf("StatusCode = %d, want %d", result.Response.StatusCode, wantStatus)
	}

	if got := requestCount.Load(); got != 1 {
		t.Errorf("request count = %d, want 1 (no credential retry)", got)
	}
}

func TestAccess_Bearer401ReturnedAsIs(t *testing.T) {
	t.Parallel()
	assertBearerStatusReturnedAsIs(t, http.StatusUnauthorized)
}

func TestAccess_Bearer403ReturnedAsIs(t *testing.T) {
	t.Parallel()
	assertBearerStatusReturnedAsIs(t, http.StatusForbidden)
}

func TestAccess_UsesOwnerHostForTokenExchangeProfile(t *testing.T) {
	t.Parallel()

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
			tshttp.WriteJSON(w, disc)

			return
		}

		if r.URL.Path == "/ocm/token" {
			if r.Header.Get("Signature") == "" {
				w.WriteHeader(http.StatusUnauthorized)

				return
			}

			if err := r.ParseForm(); err != nil {
				w.WriteHeader(http.StatusBadRequest)

				return
			}

			tokenGrantType = r.FormValue("grant_type")
			if tokenGrantType != "authorization_code" {
				w.WriteHeader(http.StatusBadRequest)
				tshttp.MustWrite(t, w, []byte(`{"error":"invalid_grant","error_description":"wrong grant"}`))

				return
			}

			w.Header().Set("Content-Type", "application/json")
			tshttp.MustWrite(t, w, []byte(`{"access_token":"owner-token","token_type":"Bearer","expires_in":3600}`))

			return
		}

		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			if r.Header.Get("Authorization") != "Bearer owner-token" {
				w.WriteHeader(http.StatusUnauthorized)

				return
			}

			w.WriteHeader(http.StatusOK)
			tshttp.MustWrite(t, w, []byte("ok"))

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
	defer tshttp.MustClose(t, result.Response.Body)

	if tokenGrantType != "authorization_code" {
		t.Fatalf("expected strict authorization_code grant_type, got %q", tokenGrantType)
	}

	if result.Response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", result.Response.StatusCode)
	}
}

// startFailingTokenExchangeServer serves discovery plus a /ocm/token endpoint
// that counts hits and always fails with status and the given OAuth error
// body.
func startFailingTokenExchangeServer(t *testing.T, tokenHits *atomic.Int32, status int, errorBody string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			tshttp.WriteJSON(w, disc)

			return
		}

		if r.URL.Path == "/ocm/token" {
			tokenHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			tshttp.MustWrite(t, w, []byte(errorBody))

			return
		}

		http.NotFound(w, r)
	}))
}

// assertTokenExchangeFailsClosed performs one token-exchange access with
// client against srvURL and asserts the failure is classified as wantReason
// with exactly one token endpoint hit.
func assertTokenExchangeFailsClosed(t *testing.T, client *Client, srvURL string, tokenHits *atomic.Int32, wantReason string) {
	t.Helper()

	_, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   srvURL,
			SharedSecret: "secret",
			WebDAVID:     "file-id",
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
		Method:   "GET",
	})
	if err == nil {
		t.Fatal("expected token exchange to fail closed")
	}

	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != wantReason {
		t.Errorf("expected reason %q, got %q: %v", wantReason, ce.ReasonCode, err)
	}

	if got := tokenHits.Load(); got != 1 {
		t.Errorf("token hits = %d, want 1 (no retry)", got)
	}
}

func TestAccess_TokenExchange401FailsClosed(t *testing.T) {
	t.Parallel()

	var tokenHits atomic.Int32

	srv := startFailingTokenExchangeServer(t, &tokenHits, http.StatusUnauthorized, `{"error":"invalid_client","error_description":"client authentication failed"}`)
	defer srv.Close()

	discClient, ctxClient := newTestClients(srv.URL)
	// Unsigned signer so the token client classifies the 401 as token_unauthorized.
	tokenClient := tokenoutgoing.NewClient(ctxClient, unsignedMockSigner{}, "local.example.com")
	client := NewClient(ctxClient, discClient, tokenClient, peerorigin.NewResolver(true))

	assertTokenExchangeFailsClosed(t, client, srv.URL, &tokenHits, reason.ReasonTokenUnauthorized)
}

func TestAccess_TokenExchange403FailsClosed(t *testing.T) {
	t.Parallel()

	var tokenHits atomic.Int32

	srv := startFailingTokenExchangeServer(t, &tokenHits, http.StatusForbidden, `{"error":"access_denied","error_description":"token exchange denied"}`)
	defer srv.Close()

	client := newExchangeAccessClient(t, srv)

	assertTokenExchangeFailsClosed(t, client, srv.URL, &tokenHits, reason.ReasonTokenForbidden)
}
