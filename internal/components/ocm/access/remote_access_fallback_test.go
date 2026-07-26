package access

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

type fallbackAccessCase struct {
	name          string
	discovery     func(host string) spec.Discovery
	tokenHandler  func(http.ResponseWriter, *http.Request)
	wantToken     string
	wantLog       bool
	wantTokenHits int32
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
			name: "capable peer exchange succeeds uses short-lived token",
			discovery: func(host string) spec.Discovery {
				return spec.Discovery{
					Enabled:       true,
					APIVersion:    "1.4.0",
					EndPoint:      "http://" + host + "/ocm",
					Capabilities:  []string{spec.CapabilityExchangeToken},
					TokenEndPoint: "http://" + host + "/ocm/token",
					ResourceTypes: []spec.ResourceType{
						{
							Name:       "file",
							ShareTypes: []string{"user"},
							Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
						},
					},
				}
			},
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"exchanged-token","token_type":"Bearer","expires_in":3600}`))
			},
			wantToken:     "exchanged-token",
			wantTokenHits: 1,
		},
		{
			name: "capable peer exchange fails falls back to shared secret",
			discovery: func(host string) spec.Discovery {
				return spec.Discovery{
					Enabled:       true,
					APIVersion:    "1.4.0",
					EndPoint:      "http://" + host + "/ocm",
					Capabilities:  []string{spec.CapabilityExchangeToken},
					TokenEndPoint: "http://" + host + "/ocm/token",
					ResourceTypes: []spec.ResourceType{
						{
							Name:       "file",
							ShareTypes: []string{"user"},
							Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
						},
					},
				}
			},
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			},
			wantToken:     sharedSecret,
			wantLog:       true,
			wantTokenHits: 1,
		},
		{
			name: "capable peer exchange fails with invalid_grant falls back to shared secret",
			discovery: func(host string) spec.Discovery {
				return spec.Discovery{
					Enabled:       true,
					APIVersion:    "1.4.0",
					EndPoint:      "http://" + host + "/ocm",
					Capabilities:  []string{spec.CapabilityExchangeToken},
					TokenEndPoint: "http://" + host + "/ocm/token",
					ResourceTypes: []spec.ResourceType{
						{
							Name:       "file",
							ShareTypes: []string{"user"},
							Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
						},
					},
				}
			},
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			},
			wantToken:     sharedSecret,
			wantLog:       true,
			wantTokenHits: 1,
		},
		{
			name: "capable peer exchange fails with invalid_request falls back to shared secret",
			discovery: func(host string) spec.Discovery {
				return spec.Discovery{
					Enabled:       true,
					APIVersion:    "1.4.0",
					EndPoint:      "http://" + host + "/ocm",
					Capabilities:  []string{spec.CapabilityExchangeToken},
					TokenEndPoint: "http://" + host + "/ocm/token",
					ResourceTypes: []spec.ResourceType{
						{
							Name:       "file",
							ShareTypes: []string{"user"},
							Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
						},
					},
				}
			},
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
			},
			wantToken:     sharedSecret,
			wantLog:       true,
			wantTokenHits: 1,
		},
		{
			name: "incapable peer uses shared secret without exchange attempt",
			discovery: func(host string) spec.Discovery {
				return spec.Discovery{
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
			},
			wantToken:     sharedSecret,
			wantTokenHits: 0,
		},
		{
			name: "signature policy prevents exchange falls back to shared secret",
			discovery: func(host string) spec.Discovery {
				return spec.Discovery{
					Enabled:       true,
					APIVersion:    "1.4.0",
					EndPoint:      "http://" + host + "/ocm",
					Capabilities:  []string{spec.CapabilityExchangeToken},
					TokenEndPoint: "http://" + host + "/ocm/token",
					Criteria:      []string{spec.CriteriaMustUseHTTPSig},
					ResourceTypes: []spec.ResourceType{
						{
							Name:       "file",
							ShareTypes: []string{"user"},
							Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
						},
					},
				}
			},
			wantToken:     sharedSecret,
			wantLog:       true,
			wantTokenHits: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var webdavHits atomic.Int32
			var tokenHits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/ocm" {
					disc := tt.discovery(r.Host)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(disc)
					return
				}
				if r.URL.Path == "/ocm/token" {
					tokenHits.Add(1)
					if tt.tokenHandler != nil {
						tt.tokenHandler(w, r)
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
			defer srv.Close()

			capture := logutil.NewCapturingLogger(slog.LevelInfo)
			prev := slog.Default()
			slog.SetDefault(capture.Logger)
			t.Cleanup(func() { slog.SetDefault(prev) })

			client, _ := newExchangeAccessClient(t, srv)

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
			defer result.Response.Body.Close()

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
			if tt.wantLog && !capture.Contains(fallbackWarning) {
				t.Errorf("expected fixed fallback warning %q, got: %s", fallbackWarning, capture.Output())
			}
			if !tt.wantLog && capture.Contains(fallbackWarning) {
				t.Errorf("unexpected fallback warning, got: %s", capture.Output())
			}
		})
	}
}
