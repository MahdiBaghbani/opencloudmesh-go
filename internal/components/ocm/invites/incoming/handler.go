// Package incoming handles inbound OCM invite-accepted protocol endpoint.
package incoming

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// Handler handles OCM invite-accepted protocol endpoint.
type Handler struct {
	outgoingRepo invites.OutgoingInviteRepo
	partyRepo    identity.PartyRepo     // for invite-accepted (look up local inviting user)
	policyEngine *peertrust.PolicyEngine // may be nil when peer trust is disabled
	providerFQDN string
	logger       *slog.Logger
	localScheme  string // scheme from PublicOrigin for comparison normalization
}

// NewHandler creates a new invites handler for the OCM protocol endpoint.
// publicOrigin is the local instance's PublicOrigin (validated at config load).
// partyRepo is used by HandleInviteAccepted to look up the local inviting user (may be nil).
// policyEngine may be nil when peer trust is disabled.
func NewHandler(
	outgoingRepo invites.OutgoingInviteRepo,
	partyRepo identity.PartyRepo,
	policyEngine *peertrust.PolicyEngine,
	localProviderFQDN string,
	publicOrigin string,
	logger *slog.Logger,
) *Handler {
	logger = logutil.NoopIfNil(logger)

	var localScheme string
	if u, err := url.Parse(publicOrigin); err == nil && u.Scheme != "" {
		localScheme = u.Scheme
	}

	return &Handler{
		outgoingRepo: outgoingRepo,
		partyRepo:    partyRepo,
		policyEngine: policyEngine,
		providerFQDN: localProviderFQDN,
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

	// Read body for preflight key-presence check
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Warn("failed to read invite-accepted request body", "error", err)
		h.sendOCMError(w, http.StatusBadRequest, "INVALID_BODY")
		return
	}

	// Preflight: check key presence for email and name before typed decode.
	// Missing key -> 400. Present but empty string -> allowed (spec does not define non-empty constraint).
	var rawFields map[string]json.RawMessage
	if err := json.Unmarshal(body, &rawFields); err != nil {
		log.Warn("failed to parse invite-accepted request", "error", err)
		h.sendOCMError(w, http.StatusBadRequest, "INVALID_BODY")
		return
	}

	if _, ok := rawFields["email"]; !ok {
		h.sendOCMError(w, http.StatusBadRequest, "EMAIL_REQUIRED")
		return
	}
	if _, ok := rawFields["name"]; !ok {
		h.sendOCMError(w, http.StatusBadRequest, "NAME_REQUIRED")
		return
	}

	// Decode into typed struct
	var req invites.InviteAcceptedRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Warn("failed to decode invite-accepted request", "error", err)
		h.sendOCMError(w, http.StatusBadRequest, "INVALID_BODY")
		return
	}

	// Spec-required field checks for remaining fields (empty string = missing)

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

	// email and name: key presence already enforced by preflight above.
	// Empty string values are allowed per spec.

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
	if invite.Status == invites.InviteStatusAccepted {
		log.Info("duplicate invite-accepted", "recipient_provider", req.RecipientProvider)
		h.sendOCMError(w, http.StatusConflict, "INVITE_ALREADY_ACCEPTED")
		return
	}

	// 10. Verify sender identity from signature (spec: 403 if not trusted)
	peerIdentity := crypto.GetPeerIdentity(ctx)
	normalizedRecipientProvider := req.RecipientProvider
	if peerIdentity != nil && peerIdentity.Authenticated {
		normalizedRecipient, err := hostport.Normalize(req.RecipientProvider, h.localScheme)
		if err != nil {
			log.Warn("failed to normalize recipient provider",
				"recipient_provider", req.RecipientProvider, "error", err)
			h.sendOCMError(w, http.StatusForbidden, "UNTRUSTED_PROVIDER")
			return
		}
		normalizedRecipientProvider = normalizedRecipient
		if peerIdentity.AuthorityForCompare != normalizedRecipient {
			log.Warn("invite-accepted sender mismatch",
				"signature_authority", peerIdentity.AuthorityForCompare,
				"recipient_provider", req.RecipientProvider)
			h.sendOCMError(w, http.StatusForbidden, "UNTRUSTED_PROVIDER")
			return
		}
	}

	// 11. Trust group policy enforcement
	if h.policyEngine != nil {
		decision := h.policyEngine.Evaluate(ctx, normalizedRecipientProvider, peerIdentity != nil && peerIdentity.Authenticated)
		if !decision.Allowed {
			h.sendOCMError(w, http.StatusForbidden, "INVITE_RECEIVER_NOT_TRUSTED")
			return
		}
	}

	// Update invite status
	if err := h.outgoingRepo.UpdateStatus(ctx, invite.ID, invites.InviteStatusAccepted, req.RecipientProvider); err != nil {
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
func (h *Handler) buildInviteAcceptedResponse(ctx context.Context, invite *invites.OutgoingInvite, log *slog.Logger) invites.InviteAcceptedResponse {
	// Legacy invite backfill (F5=A): if CreatedByUserID is empty, return placeholder
	if invite.CreatedByUserID == "" {
		return invites.InviteAcceptedResponse{
			UserID: address.FormatOutgoing("unknown", h.providerFQDN),
			Email:  "",
			Name:   "",
		}
	}

	// Look up the local inviting user
	if h.partyRepo == nil {
		log.Error("partyRepo not available for invite-accepted local user lookup")
		return invites.InviteAcceptedResponse{
			UserID: address.FormatOutgoing("unknown", h.providerFQDN),
			Email:  "",
			Name:   "",
		}
	}

	localUser, err := h.partyRepo.Get(ctx, invite.CreatedByUserID)
	if err != nil {
		log.Error("failed to look up local inviting user",
			"created_by_user_id", invite.CreatedByUserID, "error", err)
		return invites.InviteAcceptedResponse{
			UserID: address.FormatOutgoing("unknown", h.providerFQDN),
			Email:  "",
			Name:   "",
		}
	}

	return invites.InviteAcceptedResponse{
		UserID: address.FormatOutgoing(localUser.ID, h.providerFQDN),
		Email:  localUser.Email,
		Name:   localUser.DisplayName,
	}
}

// sendOCMError sends an OCM-API spec base Error response: {"message":"..."}.
func (h *Handler) sendOCMError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"message": message,
	})
}
