// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package webdav_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/webdav"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

func TestHandler_DoesNotLogSensitiveValues(t *testing.T) {
	tests := []struct {
		name         string
		bearerToken  string
		sharedSecret string
	}{
		{
			name:         "primary bearer token",
			bearerToken:  "bearer-token-must-not-log",
			sharedSecret: "shared-secret-must-not-log",
		},
		{
			name:         "second bearer token",
			bearerToken:  "bearer-token-second-must-not-log",
			sharedSecret: "shared-secret-second-must-not-log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := outgoing.NewMemoryOutgoingShareRepo()

			tmpFile, err := os.CreateTemp("", "webdav-logs-*")
			if err != nil {
				t.Fatalf("create temp file: %v", err)
			}

			t.Cleanup(func() {
				if err := os.Remove(tmpFile.Name()); err != nil {
					t.Errorf("remove temp file: %v", err)
				}
			})

			if _, err := tmpFile.WriteString("payload"); err != nil {
				t.Fatalf("write temp file: %v", err)
			}

			if err := tmpFile.Close(); err != nil {
				t.Fatalf("close temp file: %v", err)
			}

			share := &outgoing.OutgoingShare{
				ShareID:      "share-logs",
				ProviderID:   "provider-logs",
				WebDAVID:     "11111111-1111-1111-1111-111111111111",
				SharedSecret: tt.sharedSecret,
				LocalPath:    tmpFile.Name(),
				ReceiverHost: "receiver.example.com",
			}
			if err := repo.Create(context.Background(), share); err != nil {
				t.Fatalf("seed share: %v", err)
			}

			tokenStore := token.NewMemoryTokenStore()
			if err := tokenStore.Store(context.Background(), &token.IssuedToken{
				AccessToken: tt.bearerToken,
				ShareID:     share.ShareID,
				ExpiresAt:   time.Now().Add(time.Hour),
			}); err != nil {
				t.Fatalf("seed token: %v", err)
			}

			capture := logutil.NewCapturingLogger(slog.LevelDebug)
			handler := webdav.NewHandler(repo, tokenStore, capture.Logger)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+share.WebDAVID, nil)
			req.Header.Set("Authorization", "Bearer "+tt.bearerToken)

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if capture.ContainsAny(
				tt.bearerToken,
				tt.sharedSecret,
				"Authorization",
				"Signature",
				"Bearer ",
			) {
				t.Fatalf("logs leaked sensitive values: %s", capture.Output())
			}
		})
	}
}
