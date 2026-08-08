// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package access

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

type fallbackAccessCase struct {
	name          string
	exchange      bool
	httpsigPolicy bool
	tokenHandler  func(t *testing.T) http.HandlerFunc
	wantToken     string
	wantLog       bool
	wantTokenHits int32
}

// fallbackDiscovery builds the mock peer discovery document: with or without
// the exchange-token capability and token endpoint, optionally gated by an
// HTTP-signature criterion.
func fallbackDiscovery(host string, exchange, httpsigPolicy bool) spec.Discovery {
	d := spec.Discovery{
		Enabled:    true,
		APIVersion: "1.4.0",
		EndPoint:   "http://" + host + "/ocm",
		ResourceTypes: []spec.ResourceType{
			{
				Name:       "file",
				ShareTypes: []string{"user"},
				Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
			},
		},
	}

	if exchange {
		d.Capabilities = []string{spec.CapabilityExchangeToken}
		d.TokenEndPoint = "http://" + host + "/ocm/token"
	}

	if httpsigPolicy {
		d.Criteria = []string{spec.CriteriaMustUseHTTPSig}
	}

	return d
}

// jsonTokenHandler answers 200 with a raw JSON token payload.
func jsonTokenHandler(payload string) func(t *testing.T) http.HandlerFunc {
	return func(t *testing.T) http.HandlerFunc {
		t.Helper()

		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustWrite(t, w, []byte(payload))
		}
	}
}

// oauthErrorHandler answers 401 with an RFC 6749 error payload.
func oauthErrorHandler(code string) func(t *testing.T) http.HandlerFunc {
	return func(t *testing.T) http.HandlerFunc {
		t.Helper()

		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			tshttp.MustWrite(t, w, []byte(`{"error":"`+code+`"}`))
		}
	}
}

// newFallbackServer starts a mock peer serving the discovery, token, and
// webdav paths one fallback case needs.
func newFallbackServer(t *testing.T, tt fallbackAccessCase, webdavHits, tokenHits *atomic.Int32) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := fallbackDiscovery(r.Host, tt.exchange, tt.httpsigPolicy)

			w.Header().Set("Content-Type", "application/json")
			tshttp.WriteJSON(w, disc)

			return
		}

		if r.URL.Path == "/ocm/token" {
			tokenHits.Add(1)

			if tt.tokenHandler != nil {
				tt.tokenHandler(t)(w, r)

				return
			}

			http.NotFound(w, r)

			return
		}

		if strings.HasPrefix(r.URL.Path, "/webdav/ocm/") {
			webdavHits.Add(1)

			if r.Header.Get("Authorization") == "Bearer "+tt.wantToken {
				w.WriteHeader(http.StatusOK)

				return
			}

			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		http.NotFound(w, r)
	}))
}

func TestAccess_OptionalExchangeFallback(t *testing.T) {
	const (
		sharedSecret    = "fallback-shared-secret"
		fallbackWarning = "optional token exchange failed; falling back to legacy shared-secret access"
	)

	// peerOAuthErrors are peer-controlled OAuth error codes that must never
	// leak into log output when the exchange-then-fallback path falls back to
	// the legacy shared-secret bearer. The exchange error is discarded; only
	// the fixed warning is logged, so peer OAuth text is absent from logs.
	peerOAuthErrors := []string{
		"invalid_client",
		"invalid_grant",
		"invalid_request",
	}

	tests := []fallbackAccessCase{
		{
			name:          "capable peer exchange succeeds uses short-lived token",
			exchange:      true,
			tokenHandler:  jsonTokenHandler(`{"access_token":"exchanged-token","token_type":"Bearer","expires_in":3600}`),
			wantToken:     "exchanged-token",
			wantTokenHits: 1,
		},
		{
			name:          "capable peer exchange fails falls back to shared secret",
			exchange:      true,
			tokenHandler:  oauthErrorHandler("invalid_client"),
			wantToken:     sharedSecret,
			wantLog:       true,
			wantTokenHits: 1,
		},
		{
			name:          "capable peer exchange fails with invalid_grant falls back to shared secret",
			exchange:      true,
			tokenHandler:  oauthErrorHandler("invalid_grant"),
			wantToken:     sharedSecret,
			wantLog:       true,
			wantTokenHits: 1,
		},
		{
			name:          "capable peer exchange fails with invalid_request falls back to shared secret",
			exchange:      true,
			tokenHandler:  oauthErrorHandler("invalid_request"),
			wantToken:     sharedSecret,
			wantLog:       true,
			wantTokenHits: 1,
		},
		{
			name:          "incapable peer uses shared secret without exchange attempt",
			wantToken:     sharedSecret,
			wantTokenHits: 0,
		},
		{
			name:          "signature policy prevents exchange falls back to shared secret",
			exchange:      true,
			httpsigPolicy: true,
			wantToken:     sharedSecret,
			wantLog:       true,
			wantTokenHits: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runFallbackCase(t, tt, sharedSecret, fallbackWarning, peerOAuthErrors)
		})
	}
}

// runFallbackCase drives one exchange-fallback scenario against the mock peer
// and asserts token choice, endpoint hit counts, and log hygiene.
func runFallbackCase(t *testing.T, tt fallbackAccessCase, sharedSecret, fallbackWarning string, peerOAuthErrors []string) {
	t.Helper()

	var (
		webdavHits atomic.Int32
		tokenHits  atomic.Int32
	)

	srv := newFallbackServer(t, tt, &webdavHits, &tokenHits)
	defer srv.Close()

	capture := logutil.NewCapturingLogger(slog.LevelInfo)
	prev := slog.Default()

	slog.SetDefault(capture.Logger)
	t.Cleanup(func() { slog.SetDefault(prev) })

	client := newExchangeAccessClient(t, srv)

	result, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       ShareStatusAccepted,
			SenderHost:   srv.URL,
			SharedSecret: sharedSecret,
			WebDAVID:     "file-123",
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

	if result.AccessToken != tt.wantToken {
		t.Errorf("AccessToken = %q, want %q", result.AccessToken, tt.wantToken)
	}

	if got := webdavHits.Load(); got != 1 {
		t.Errorf("webdav hits = %d, want 1", got)
	}

	if got := tokenHits.Load(); got != tt.wantTokenHits {
		t.Errorf("token exchange attempts = %d, want %d", got, tt.wantTokenHits)
	}

	assertFallbackLogs(t, capture, tt.wantLog, sharedSecret, fallbackWarning, peerOAuthErrors)
}

// assertFallbackLogs checks the fallback path never leaks secrets or
// peer-controlled OAuth error text, and emits the fixed warning iff wanted.
func assertFallbackLogs(t *testing.T, capture *logutil.CapturingLogger, wantLog bool, sharedSecret, fallbackWarning string, peerOAuthErrors []string) {
	t.Helper()

	if capture.ContainsAny(
		sharedSecret,
		"Authorization",
		"Bearer ",
	) {
		t.Errorf("logs leaked sensitive values: %s", capture.Output())
	}

	// Peer-controlled OAuth error text must never leak into logs. The
	// exchange error is discarded and only the fixed warning is logged;
	// peer OAuth text such as invalid_client is absent from logs.
	if capture.ContainsAny(peerOAuthErrors...) {
		t.Errorf("logs leaked peer OAuth error text: %s", capture.Output())
	}

	if wantLog && !capture.Contains(fallbackWarning) {
		t.Errorf("expected fixed fallback warning %q, got: %s", fallbackWarning, capture.Output())
	}

	if !wantLog && capture.Contains(fallbackWarning) {
		t.Errorf("unexpected fallback warning, got: %s", capture.Output())
	}
}
