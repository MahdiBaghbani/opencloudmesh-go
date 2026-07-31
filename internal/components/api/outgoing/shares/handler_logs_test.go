// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

func TestHandleCreate_DoesNotLogSensitiveValues(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		signature     string
	}{
		{
			name:          "primary request credentials",
			authorization: "outgoing-share-auth-token-must-not-log",
			signature:     "outgoing-share-signature-must-not-log",
		},
		{
			name:          "second request credentials",
			authorization: "outgoing-share-auth-second-must-not-log",
			signature:     "outgoing-share-signature-second-must-not-log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, postCount := makeReceiverTLSServer(t,
				[]string{"exchange-token"},
				[]string{"must-exchange-token"},
			)
			t.Cleanup(srv.Close)

			user := &identity.User{ID: "user-uuid", Username: "alice"}
			repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
			discClient, ctxClient := makeTLSClients()
			capture := logutil.NewCapturingLogger(slog.LevelDebug)
			handler := outgoingshares.NewHandler(
				repo,
				discClient,
				ctxClient,
				makeTestSigner(t),
				testProvider,
				testCurrentUser(user),
				capture.Logger,
				&stubResolver{facts: policy.NewCodeFlow().Evaluate()},
				"https://example.com/ocm/token",
			)
			handler.SetAllowedPaths([]string{"/tmp"})
			handler.SetPeerOrigin(peerorigin.NewResolver(false))

			tmpFile := createTempShareFile(t, "outgoing-logs-*")
			receiverHost := srv.Listener.Addr().String()

			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"/api/shares/outgoing",
				bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)),
			)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tt.authorization)
			req.Header.Set("Signature", tt.signature)

			w := httptest.NewRecorder()
			handler.HandleCreate(w, req)

			if w.Code != http.StatusCreated {
				t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
			}

			if postCount.Load() == 0 {
				t.Fatal("expected outbound share POST")
			}

			createdShares, err := repo.List(t.Context())
			if err != nil {
				t.Fatalf("list created shares: %v", err)
			}

			if len(createdShares) != 1 {
				t.Fatalf("created share count = %d, want 1", len(createdShares))
			}

			if capture.ContainsAny(
				tt.authorization,
				tt.signature,
				createdShares[0].SharedSecret,
				"Authorization",
				"Signature",
				"Bearer ",
			) {
				t.Fatalf("logs leaked sensitive values: %s", capture.Output())
			}
		})
	}
}
