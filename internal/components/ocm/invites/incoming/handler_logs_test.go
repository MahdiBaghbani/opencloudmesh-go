package incoming_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

func TestHandler_DoesNotLogSensitiveValues(t *testing.T) {
	tests := []struct {
		name          string
		inviteToken   string
		authorization string
		signature     string
		seedInvite    bool
		wantStatus    int
	}{
		{
			name:          "accepted invite",
			inviteToken:   "invite-token-accepted-must-not-log",
			authorization: "invite-auth-accepted-must-not-log",
			signature:     "invite-signature-accepted-must-not-log",
			seedInvite:    true,
			wantStatus:    http.StatusOK,
		},
		{
			name:          "unknown invite token",
			inviteToken:   "invite-token-unknown-must-not-log",
			authorization: "invite-auth-unknown-must-not-log",
			signature:     "invite-signature-unknown-must-not-log",
			wantStatus:    http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
			partyRepo := identity.NewMemoryPartyRepo()

			_ = partyRepo.Create(context.Background(), &identity.User{
				ID:          "creator-id",
				Username:    "alice",
				DisplayName: "Alice",
			})
			if tt.seedInvite {
				_ = repo.Create(context.Background(), &invitesoutgoing.OutgoingInvite{
					ID:              "invite-id",
					Token:           tt.inviteToken,
					ProviderFQDN:    testProvider,
					CreatedByUserID: "creator-id",
					Status:          invites.InviteStatusPending,
					ExpiresAt:       time.Now().Add(time.Hour),
				})
			}

			capture := logutil.NewCapturingLogger(slog.LevelDebug)
			handler := incoming.NewHandler(
				repo,
				partyRepo,
				nil,
				testProvider,
				testScheme,
				capture.Logger,
			)

			body, _ := json.Marshal(map[string]string{
				"recipientProvider": testProvider,
				"token":             tt.inviteToken,
				"userID":            "user-123",
				"email":             "bob@example.com",
				"name":              "Bob",
			})
			req := httptest.NewRequest(
				http.MethodPost,
				"/ocm/invite-accepted",
				bytes.NewReader(body),
			)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tt.authorization)
			req.Header.Set("Signature", tt.signature)
			req = req.WithContext(appctx.WithLogger(req.Context(), capture.Logger))
			w := httptest.NewRecorder()
			handler.HandleInviteAccepted(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("expected %d, got %d: %s", tt.wantStatus, w.Code, w.Body.String())
			}

			if capture.ContainsAny(
				tt.inviteToken,
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
