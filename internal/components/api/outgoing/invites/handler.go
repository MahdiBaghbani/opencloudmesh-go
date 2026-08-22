// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package invites provides the session-gated handler for POST /api/invites/outgoing (create invite tokens).
package invites

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// DefaultInviteTTL is the default time-to-live for invites.
const DefaultInviteTTL = 7 * 24 * time.Hour

// Handler serves POST /api/invites/outgoing to create invite tokens.
type Handler struct {
	outgoingRepo  invitesoutgoing.OutgoingInviteRepo
	localProvider string // raw host[:port] for invite token generation
	currentUser   func(context.Context) (*identity.User, error)
	logger        *slog.Logger
}

// NewHandler returns a Handler with the given dependencies.
func NewHandler(
	outgoingRepo invitesoutgoing.OutgoingInviteRepo,
	localProvider string,
	currentUser func(context.Context) (*identity.User, error),
	logger *slog.Logger,
) *Handler {
	logger = logutil.NoopIfNil(logger)

	return &Handler{
		outgoingRepo:  outgoingRepo,
		localProvider: localProvider,
		currentUser:   currentUser,
		logger:        logger,
	}
}

// HandleCreateOutgoing handles POST /api/invites/outgoing. This product
// route is a second invite-token writer beside the validator session mint
// that binds one canonical outgoing invite per interactive run.
func (h *Handler) HandleCreateOutgoing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	var req invites.CreateOutgoingRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, api.ReasonBadRequest, "failed to parse request body")

			return
		}
	}

	ctx := r.Context()

	user, err := h.currentUser(ctx)
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")

		return
	}

	token, err := generateToken()
	if err != nil {
		h.logger.Error("failed to generate invite token", "error", err)
		api.WriteInternalError(w, "failed to generate token")

		return
	}

	inviteString := invites.BuildInviteString(token, h.localProvider)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:           token,
		ProviderFQDN:    h.localProvider,
		InviteString:    inviteString,
		RecipientEmail:  req.RecipientEmail,
		CreatedByUserID: user.ID,
		ExpiresAt:       time.Now().Add(DefaultInviteTTL),
		Status:          invites.InviteStatusPending,
	}

	if err := h.outgoingRepo.Create(ctx, invite); err != nil {
		h.logger.Error("failed to create invite", "error", err)
		api.WriteInternalError(w, "failed to create invite")

		return
	}

	h.logger.Info("invite created", "id", invite.ID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(invites.CreateOutgoingResponse{
		InviteString: inviteString,
		Token:        token,
		ProviderFQDN: h.localProvider,
		ExpiresAt:    invite.ExpiresAt,
	}); err != nil {
		h.logger.Error("failed to encode invite response", "error", err)
	}
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("api: generate invite token: %w", err)
	}

	return hex.EncodeToString(b), nil
}
