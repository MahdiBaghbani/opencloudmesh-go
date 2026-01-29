package invites

import (
	"context"
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

// Handler handles OCM invite-accepted protocol endpoint.
type Handler struct {
	outgoingRepo OutgoingInviteRepo
	partyRepo    identity.PartyRepo // for invite-accepted (look up local inviting user)
	providerFQDN string
	logger       *slog.Logger
	localScheme  string // scheme from PublicOrigin for comparison normalization
}

// NewHandler creates a new invites handler for the OCM protocol endpoint.
// publicOrigin is the local instance's PublicOrigin (validated at config load).
// partyRepo is used by HandleInviteAccepted to look up the local inviting user (may be nil).
func NewHandler(
	outgoingRepo OutgoingInviteRepo,
	partyRepo identity.PartyRepo,
	providerFQDN string,
	publicOrigin string,
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

	// Spec-required field checks: all five AcceptedInvite fields are required.

	// 1. Empty/missing recipientProvider
	if req.RecipientProvider == "" {
		h.sendOCMError(w, http.StatusBadRequest, "RECIPIENT_PROVIDER_REQUIRED")
		return
	}

	// 2. recipientProvider must be an FQDN (no scheme)
	if strings.Contains(req.RecipientProvider, "://") {
		h.sendOCMError(w, http.StatusBadRequest, "INVALID_RECIPIENT_PROVIDER")
		return
	}

	// 3. Empty/missing token
	if req.Token == "" {
		h.sendOCMError(w, http.StatusBadRequest, "TOKEN_REQUIRED")
		return
	}

	// 4. Empty/missing userID
	if req.UserID == "" {
		h.sendOCMError(w, http.StatusBadRequest, "USERID_REQUIRED")
		return
	}

	// 5. Empty/missing email (spec: required in AcceptedInvite schema)
	if req.Email == "" {
		h.sendOCMError(w, http.StatusBadRequest, "EMAIL_REQUIRED")
		return
	}

	// 6. Empty/missing name (spec: required in AcceptedInvite schema)
	if req.Name == "" {
		h.sendOCMError(w, http.StatusBadRequest, "NAME_REQUIRED")
		return
	}

	ctx := r.Context()

	// 7. Token not found -> TOKEN_INVALID (spec: 400, not 404)
	invite, err := h.outgoingRepo.GetByToken(ctx, req.Token)
	if err != nil {
		log.Warn("invite-accepted for unknown token", "recipient_provider", req.RecipientProvider)
		h.sendOCMError(w, http.StatusBadRequest, "TOKEN_INVALID")
		return
	}

	// 8. Token expired -> TOKEN_EXPIRED
	if !invite.ExpiresAt.IsZero() && time.Now().After(invite.ExpiresAt) {
		h.sendOCMError(w, http.StatusBadRequest, "TOKEN_EXPIRED")
		return
	}

	// 9. Already accepted -> 409 INVITE_ALREADY_ACCEPTED (spec-mandated)
	if invite.Status == InviteStatusAccepted {
		log.Info("duplicate invite-accepted", "recipient_provider", req.RecipientProvider)
		h.sendOCMError(w, http.StatusConflict, "INVITE_ALREADY_ACCEPTED")
		return
	}

	// 10. Verify sender identity from signature (spec: 403 if not trusted)
	peerIdentity := crypto.GetPeerIdentity(ctx)
	if peerIdentity != nil && peerIdentity.Authenticated {
		normalizedRecipient, err := hostport.Normalize(req.RecipientProvider, h.localScheme)
		if err != nil {
			log.Warn("failed to normalize recipient provider",
				"recipient_provider", req.RecipientProvider, "error", err)
			h.sendOCMError(w, http.StatusForbidden, "UNTRUSTED_PROVIDER")
			return
		}
		if peerIdentity.AuthorityForCompare != normalizedRecipient {
			log.Warn("invite-accepted sender mismatch",
				"signature_authority", peerIdentity.AuthorityForCompare,
				"recipient_provider", req.RecipientProvider)
			h.sendOCMError(w, http.StatusForbidden, "UNTRUSTED_PROVIDER")
			return
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

// sendOCMError sends an OCM-API spec base Error response: {"message":"..."}.
// Used by OCM protocol endpoints (invite-accepted).
func (h *Handler) sendOCMError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"message": message,
	})
}

