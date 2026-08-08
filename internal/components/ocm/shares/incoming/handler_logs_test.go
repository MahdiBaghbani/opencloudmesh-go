// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

func TestHandler_DoesNotLogSensitiveValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		sharedSecret  string
		authorization string
		signature     string
	}{
		{
			name:          "shared secret",
			sharedSecret:  "shared-secret-must-not-log",
			authorization: "incoming-share-auth-token-must-not-log",
			signature:     "incoming-share-signature-must-not-log",
		},
		{
			name:          "second shared secret",
			sharedSecret:  "shared-secret-second-must-not-log",
			authorization: "incoming-share-auth-second-must-not-log",
			signature:     "incoming-share-signature-second-must-not-log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repo := tsrepos.OpenMemory(t).IncomingShares
			partyRepo := setupTestPartyRepo(t)
			capture := logutil.NewCapturingLogger(slog.LevelDebug)
			handler := incoming.NewHandler(
				repo,
				partyRepo,
				nil,
				nil,
				nil,
				false,
				"localhost:9200",
				"https",
				policy.NewPeerMappingResolver(policy.NewCodeFlow(), nil, config.CompatibilityScopeGlobal),
			)

			body := validShareBodyWithOwnerAndSenderHosts(
				"alice@localhost:9200",
				"owner.example.com",
				"sender.example.com",
				"provider-logs",
			)
			bodyBytes := bytes.ReplaceAll(
				[]byte(body),
				[]byte("secret123"),
				[]byte(tt.sharedSecret),
			)

			req := httptest.NewRequestWithContext(context.Background(),
				http.MethodPost,
				"/ocm/shares",
				bytes.NewReader(bodyBytes),
			)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tt.authorization)
			req.Header.Set("Signature", tt.signature)
			req = req.WithContext(appctx.WithLogger(req.Context(), capture.Logger))
			w := httptest.NewRecorder()
			handler.CreateShare(w, req)

			if w.Code != http.StatusCreated && w.Code != http.StatusOK {
				t.Fatalf("expected success status, got %d: %s", w.Code, w.Body.String())
			}

			if capture.ContainsAny(
				tt.sharedSecret,
				tt.authorization,
				tt.signature,
				"Authorization",
				"Signature",
				"Bearer ",
			) {
				t.Fatalf("logs leaked sensitive values: %s", capture.Output())
			}
		})
	}
}
