package invites

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// DefaultInviteTTL is the default time-to-live for invites.
const DefaultInviteTTL = 7 * 24 * time.Hour // 7 days

// Handler handles OCM invite endpoints.
type Handler struct {
	outgoingRepo OutgoingInviteRepo
	providerFQDN string
	logger       *slog.Logger
	localScheme  string // scheme from PublicOrigin for comparison normalization
}

// NewHandler creates a new invites handler.
// publicOrigin is the local instance's PublicOrigin (validated at config load).
func NewHandler(outgoingRepo OutgoingInviteRepo, providerFQDN string, publicOrigin string, logger *slog.Logger) *Handler {
	var localScheme string
	if u, err := url.Parse(publicOrigin); err == nil && u.Scheme != "" {
		localScheme = u.Scheme
	}

	return &Handler{
		outgoingRepo: outgoingRepo,
		providerFQDN: providerFQDN,
		logger:       logger,
		localScheme:  localScheme,
	}
}

// HandleInviteAccepted handles POST /ocm/invite-accepted.
func (h *Handler) HandleInviteAccepted(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get request-scoped logger with request correlation fields
	log := appctx.GetLogger(r.Context())

	// Strict mode: only accept JSON
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		h.sendError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}

	var req InviteAcceptedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("failed to parse invite-accepted request", "error", err)
		h.sendError(w, http.StatusBadRequest, "invalid_json", "failed to parse request body")
		return
	}

	// Validate required fields
	if req.Token == "" {
		h.sendError(w, http.StatusBadRequest, "missing_field", "token is required")
		return
	}
	if req.RecipientProvider == "" {
		h.sendError(w, http.StatusBadRequest, "missing_field", "recipientProvider is required")
		return
	}

	// Validate recipientProvider format (no scheme allowed)
	if strings.Contains(req.RecipientProvider, "://") {
		h.sendError(w, http.StatusBadRequest, "invalid_format", "recipientProvider must not contain scheme")
		return
	}

	ctx := r.Context()

	// Look up the invite by token
	invite, err := h.outgoingRepo.GetByToken(ctx, req.Token)
	if err != nil {
		log.Warn("invite-accepted for unknown token", "recipient_provider", req.RecipientProvider)
		h.sendError(w, http.StatusNotFound, "token_not_found", "no invite found for token")
		return
	}

	// Check if already accepted
	if invite.Status == InviteStatusAccepted {
		// Note: Do not log token here (secret). Only log recipient_provider for correlation.
		log.Info("duplicate invite-accepted", "recipient_provider", req.RecipientProvider)
		// Idempotent success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(InviteAcceptedResponse{
			UserID: req.UserID,
			Email:  req.Email,
			Name:   req.Name,
		})
		return
	}

	// Check if expired
	if !invite.ExpiresAt.IsZero() && time.Now().After(invite.ExpiresAt) {
		h.sendError(w, http.StatusGone, "invite_expired", "invite has expired")
		return
	}

	// Verify sender identity from signature if available
	peerIdentity := crypto.GetPeerIdentity(ctx)
	if peerIdentity != nil && peerIdentity.Authenticated {
		normalizedRecipient, err := hostport.Normalize(req.RecipientProvider, h.localScheme)
		if err != nil {
			log.Warn("failed to normalize recipient provider",
				"recipient_provider", req.RecipientProvider, "error", err)
		} else if peerIdentity.AuthorityForCompare != normalizedRecipient {
			log.Warn("invite-accepted sender mismatch",
				"signature_authority", peerIdentity.AuthorityForCompare,
				"recipient_provider", req.RecipientProvider)
			// In strict mode, this would be a rejection
			// For now, log but allow
		}
	}

	// Update invite status
	if err := h.outgoingRepo.UpdateStatus(ctx, invite.ID, InviteStatusAccepted, req.RecipientProvider); err != nil {
		log.Error("failed to update invite status", "id", invite.ID, "error", err)
		h.sendError(w, http.StatusInternalServerError, "update_failed", "failed to update invite status")
		return
	}

	// Note: Do not log token here (secret). Only log recipient_provider and user_id for correlation.
	log.Info("invite accepted",
		"recipient_provider", req.RecipientProvider,
		"user_id", req.UserID)

	// Return success with user info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(InviteAcceptedResponse{
		UserID: req.UserID,
		Email:  req.Email,
		Name:   req.Name,
	})
}

// HandleCreateOutgoing handles POST /api/invites/outgoing.
func (h *Handler) HandleCreateOutgoing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateOutgoingRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.sendError(w, http.StatusBadRequest, "invalid_json", "failed to parse request body")
			return
		}
	}

	ctx := r.Context()

	// Generate a secure random token
	token, err := generateToken()
	if err != nil {
		h.logger.Error("failed to generate invite token", "error", err)
		h.sendError(w, http.StatusInternalServerError, "token_generation_failed", "failed to generate token")
		return
	}

	// Build the invite string
	inviteString := BuildInviteString(token, h.providerFQDN)

	invite := &OutgoingInvite{
		Token:          token,
		ProviderFQDN:   h.providerFQDN,
		InviteString:   inviteString,
		RecipientEmail: req.RecipientEmail,
		ExpiresAt:      time.Now().Add(DefaultInviteTTL),
		Status:         InviteStatusPending,
	}

	if err := h.outgoingRepo.Create(ctx, invite); err != nil {
		h.logger.Error("failed to create invite", "error", err)
		h.sendError(w, http.StatusInternalServerError, "create_failed", "failed to create invite")
		return
	}

	// Note: Do not log token here (secret). Only log invite ID for correlation.
	h.logger.Info("invite created", "id", invite.ID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(CreateOutgoingResponse{
		InviteString: inviteString,
		Token:        token,
		ProviderFQDN: h.providerFQDN,
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

// sendError sends a JSON error response.
func (h *Handler) sendError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":       code,
		"description": message,
	})
}
