// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outgoing_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

type logSentinelSigner struct {
	signature string
}

func (s logSentinelSigner) Sign(req *http.Request) error {
	req.Header.Set("Signature", s.signature)
	return nil
}

func TestClient_Exchange_DoesNotLogSensitiveValues(t *testing.T) {
	tests := []struct {
		name         string
		sharedSecret string
		accessToken  string
		signature    string
	}{
		{
			name:         "primary exchange values",
			sharedSecret: "outgoing-code-must-not-log",
			accessToken:  "outgoing-access-token-must-not-log",
			signature:    "outgoing-signature-must-not-log",
		},
		{
			name:         "second exchange values",
			sharedSecret: "outgoing-code-second-must-not-log",
			accessToken:  "outgoing-access-token-second-must-not-log",
			signature:    "outgoing-signature-second-must-not-log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture := logutil.NewCapturingLogger(slog.LevelDebug)
			prev := slog.Default()
			slog.SetDefault(capture.Logger)
			t.Cleanup(func() { slog.SetDefault(prev) })

			server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("token exchange method = %s, want POST", r.Method)
				}
				if got := r.Header.Get("Signature"); got != tt.signature {
					t.Errorf("token exchange signature = %q, want %q", got, tt.signature)
				}
				if err := r.ParseForm(); err != nil {
					t.Errorf("parse token exchange form: %v", err)
				}
				if got := r.FormValue("code"); got != tt.sharedSecret {
					t.Errorf("token exchange code = %q, want %q", got, tt.sharedSecret)
				}

				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(token.TokenResponse{
					AccessToken: tt.accessToken,
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				})
			}))
			t.Cleanup(server.Close)

			httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
				SSRF: config.SSRFConfig{Mode: "off"},
			}, nil))
			client := tokenoutgoing.NewClient(
				httpClient,
				dummyDiscClient(),
				logSentinelSigner{signature: tt.signature},
				makePolicy("strict", nil),
				"my-instance.example.com",
			)

			result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
				TokenEndPoint: server.URL,
				PeerDomain:    "peer.example.com",
				SharedSecret:  tt.sharedSecret,
			})
			if err != nil {
				t.Fatalf("token exchange failed: %v", err)
			}
			if result.AccessToken != tt.accessToken {
				t.Fatalf("access token = %q, want %q", result.AccessToken, tt.accessToken)
			}

			if capture.ContainsAny(
				tt.sharedSecret,
				tt.accessToken,
				tt.signature,
				"Authorization",
				"Signature",
				"code=",
				"access_token",
				"Bearer ",
			) {
				t.Fatalf("logs leaked sensitive values: %s", capture.Output())
			}
		})
	}
}
