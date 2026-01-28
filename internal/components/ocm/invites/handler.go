package invites

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// DefaultInviteTTL is the default time-to-live for invites.
const DefaultInviteTTL = 7 * 24 * time.Hour // 7 days

// Handler handles OCM invite endpoints.
type Handler struct {
	outgoingRepo OutgoingInviteRepo
	partyRepo    identity.PartyRepo // for invite-accepted (look up local inviting user)
	providerFQDN string
	logger       *slog.Logger
	localScheme  string // scheme from PublicOrigin for comparison normalization
	currentUser  func(context.Context) (*identity.User, error) // for create-outgoing (session user)
}

// NewHandler creates a new invites handler.
// publicOrigin is the local instance's PublicOrigin (validated at config load).
// partyRepo is used by HandleInviteAccepted to look up the local inviting user (may be nil).
// currentUser is used by HandleCreateOutgoing to track the creating user (may be nil).
func NewHandler(
	outgoingRepo OutgoingInviteRepo,
	partyRepo identity.PartyRepo,
	providerFQDN string,
	publicOrigin string,
	currentUser func(context.Context) (*identity.User, error),
	logger *slog.Logger,
) *Handler {
	var localScheme string
	if u, err := url.Parse(publicOrigin); err == nil && u.Scheme != "" {
		localScheme = u.Scheme
	}

	return &Handler{
		outgoingRepo: outgoingRepo,
		partyRepo:    partyRepo,
		providerFQDN: providerFQDN,
		logger:       logger,
		localScheme:  localScheme,
		currentUser:  currentUser,
	}
}

// HandleInviteAccepted handles POST /ocm/invite-accepted.
// Implements the OCM-API spec error table (F3=A).
func (h *Handler) HandleInviteAccepted(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log := appctx.GetLogger(r.Context())

	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		h.sendOCMError(w, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE")
		return
	}

	var req InviteAcceptedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("failed to parse invite-accepted request", "error", err)
		h.sendOCMError(w, http.StatusBadRequest, "INVALID_BODY")
		return
	}

	// 1. Empty/missing token -> TOKEN_REQUIRED
	if req.Token == "" {
		h.sendOCMError(w, http.StatusBadRequest, "TOKEN_REQUIRED")
		return
	}

	ctx := r.Context()

	// 2. Token not found -> TOKEN_INVALID (spec: 400, not 404)
	invite, err := h.outgoingRepo.GetByToken(ctx, req.Token)
	if err != nil {
		log.Warn("invite-accepted for unknown token", "recipient_provider", req.RecipientProvider)
		h.sendOCMError(w, http.StatusBadRequest, "TOKEN_INVALID")
		return
	}

	// 3. Token expired -> TOKEN_EXPIRED
	if !invite.ExpiresAt.IsZero() && time.Now().After(invite.ExpiresAt) {
		h.sendOCMError(w, http.StatusBadRequest, "TOKEN_EXPIRED")
		return
	}

	// 4. Empty/missing userID -> USERID_REQUIRED
	if req.UserID == "" {
		h.sendOCMError(w, http.StatusBadRequest, "USERID_REQUIRED")
		return
	}

	// 5. Invalid recipientProvider (contains scheme) -> INVALID_RECIPIENT_PROVIDER
	if strings.Contains(req.RecipientProvider, "://") {
		h.sendOCMError(w, http.StatusBadRequest, "INVALID_RECIPIENT_PROVIDER")
		return
	}

	// 6. Already accepted -> 409 INVITE_ALREADY_ACCEPTED (spec-mandated)
	if invite.Status == InviteStatusAccepted {
		log.Info("duplicate invite-accepted", "recipient_provider", req.RecipientProvider)
		h.sendOCMError(w, http.StatusConflict, "INVITE_ALREADY_ACCEPTED")
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
		}
	}

	// Update invite status
	if err := h.outgoingRepo.UpdateStatus(ctx, invite.ID, InviteStatusAccepted, req.RecipientProvider); err != nil {
		log.Error("failed to update invite status", "id", invite.ID, "error", err)
		h.sendOCMError(w, http.StatusInternalServerError, "UPDATE_FAILED")
		return
	}

	log.Info("invite accepted",
		"recipient_provider", req.RecipientProvider,
		"user_id", req.UserID)

	// Build response with the LOCAL inviting user's identity (not the remote user's)
	response := h.buildInviteAcceptedResponse(ctx, invite, log)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// buildInviteAcceptedResponse returns the local inviting user's identity for the
// invite-accepted response. Handles the CreatedByUserID backfill for legacy invites (F5=A).
func (h *Handler) buildInviteAcceptedResponse(ctx context.Context, invite *OutgoingInvite, log *slog.Logger) InviteAcceptedResponse {
	// Legacy invite backfill (F5=A): if CreatedByUserID is empty, return placeholder
	if invite.CreatedByUserID == "" {
		return InviteAcceptedResponse{
			UserID: address.FormatOutgoing("unknown", h.providerFQDN),
			Email:  "",
			Name:   "",
		}
	}

	// Look up the local inviting user
	if h.partyRepo == nil {
		log.Error("partyRepo not available for invite-accepted local user lookup")
		return InviteAcceptedResponse{
			UserID: address.FormatOutgoing("unknown", h.providerFQDN),
			Email:  "",
			Name:   "",
		}
	}

	localUser, err := h.partyRepo.Get(ctx, invite.CreatedByUserID)
	if err != nil {
		log.Error("failed to look up local inviting user",
			"created_by_user_id", invite.CreatedByUserID, "error", err)
		return InviteAcceptedResponse{
			UserID: address.FormatOutgoing("unknown", h.providerFQDN),
			Email:  "",
			Name:   "",
		}
	}

	return InviteAcceptedResponse{
		UserID: address.FormatOutgoing(localUser.ID, h.providerFQDN),
		Email:  localUser.Email,
		Name:   localUser.DisplayName,
	}
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

	// Track the creating user for invite-accepted response generation
	var createdByUserID string
	if h.currentUser != nil {
		if user, err := h.currentUser(ctx); err == nil {
			createdByUserID = user.ID
		}
	}

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
		Token:           token,
		ProviderFQDN:    h.providerFQDN,
		InviteString:    inviteString,
		RecipientEmail:  req.RecipientEmail,
		CreatedByUserID: createdByUserID,
		ExpiresAt:       time.Now().Add(DefaultInviteTTL),
		Status:          InviteStatusPending,
	}

	if err := h.outgoingRepo.Create(ctx, invite); err != nil {
		h.logger.Error("failed to create invite", "error", err)
		h.sendError(w, http.StatusInternalServerError, "create_failed", "failed to create invite")
		return
	}

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

// sendOCMError sends an OCM-API spec base Error response: {"message":"..."}.
// Used by OCM protocol endpoints (invite-accepted).
func (h *Handler) sendOCMError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"message": message,
	})
}

// sendError sends a JSON error response for local API endpoints.
func (h *Handler) sendError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":       code,
		"description": message,
	})
}
