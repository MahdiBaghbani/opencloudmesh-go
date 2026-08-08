// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

func TestHandler_DoesNotLogSensitiveValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		setupShare   bool
		sharedSecret string
		clientID     string
		wantStatus   int
	}{
		{
			name:         "valid exchange",
			setupShare:   true,
			sharedSecret: "incoming-code-must-not-log",
			clientID:     "receiver.example.com",
			wantStatus:   http.StatusOK,
		},
		{
			name:         "second valid exchange",
			setupShare:   true,
			sharedSecret: "incoming-code-second-must-not-log",
			clientID:     "receiver.example.com",
			wantStatus:   http.StatusOK,
		},
		{
			name:         "unknown code",
			setupShare:   false,
			sharedSecret: "incoming-unknown-code-must-not-log",
			clientID:     "receiver.example.com",
			wantStatus:   http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			shareRepo := tsrepos.OpenMemory(t).OutgoingShares
			tokenStore := token.NewMemoryTokenStore()
			capture := logutil.NewCapturingLogger(slog.LevelDebug)
			handler := tokenincoming.NewHandler(
				shareRepo,
				tokenStore,
				enabledSettings(),
				enabledCodeFlow(),
				"https://local.example.com",
			)

			if tt.setupShare {
				share := &sharesoutgoing.OutgoingShare{
					ProviderID:   "provider-logs-" + tt.name,
					WebDAVID:     "webdav-logs-" + tt.name,
					SharedSecret: tt.sharedSecret,
					ReceiverHost: tt.clientID,
					LocalPath:    "/tmp/test.txt",
				}
				if err := shareRepo.Create(context.Background(), share); err != nil {
					t.Fatalf("Create: %v", err)
				}
			}

			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("client_id", tt.clientID)
			form.Set("code", tt.sharedSecret)

			req := httptest.NewRequestWithContext(context.Background(),
				http.MethodPost,
				"/ocm/token",
				strings.NewReader(form.Encode()),
			)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(appctx.WithLogger(req.Context(), capture.Logger))
			w := httptest.NewRecorder()
			handler.HandleToken(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tt.wantStatus, w.Code, w.Body.String())
			}

			sensitive := []string{
				tt.sharedSecret,
				"code=",
				"access_token",
			}
			if tt.wantStatus == http.StatusOK {
				var resp token.TokenResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if resp.AccessToken == "" {
					t.Fatal("access_token is empty")
				}

				sensitive = append(sensitive, resp.AccessToken)
			}

			if capture.ContainsAny(sensitive...) {
				t.Fatalf("logs leaked sensitive values: %s", capture.Output())
			}
		})
	}
}
