// Package invites implements the session-gated outgoing invite handler.
// Handles POST /api/invites/outgoing for creating invite tokens.
package invites

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

// Handler handles outgoing invite creation.
type Handler struct {
	outgoingRepo  invitesoutgoing.OutgoingInviteRepo
	localProvider string // raw host[:port] for invite token generation
	currentUser   func(context.Context) (*identity.User, error)
	logger        *slog.Logger
}

// NewHandler creates a new outgoing invites handler.
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

// HandleCreateOutgoing handles POST /api/invites/outgoing.
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

	// Track the creating user for invite-accepted response generation
	var createdByUserID string
	if h.currentUser != nil {
		if user, err := h.currentUser(ctx); err == nil {
			createdByUserID = user.ID
		}
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
		CreatedByUserID: createdByUserID,
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
	json.NewEncoder(w).Encode(invites.CreateOutgoingResponse{
		InviteString: inviteString,
		Token:        token,
		ProviderFQDN: h.localProvider,
		ExpiresAt:    invite.ExpiresAt,
	})
}

// generateToken creates a cryptographically secure random token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
