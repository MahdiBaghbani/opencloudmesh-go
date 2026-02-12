// Package incoming handles POST /ocm/invite-accepted.
// See https://github.com/cs3org/OCM-API/blob/615192eeff00bcd479364dfa9c1f91641ac7b505/IETF-RFC.md?plain=1#invite-acceptance-request-details
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
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

type Handler struct {
	outgoingRepo invitesoutgoing.OutgoingInviteRepo
	partyRepo    identity.PartyRepo     // for invite-accepted (look up local inviting user)
	policyEngine *peertrust.PolicyEngine // may be nil when peer trust is disabled
	providerFQDN string
	logger       *slog.Logger
	localScheme  string // scheme from PublicOrigin for comparison normalization
}

// NewHandler creates the invite-accepted handler. partyRepo looks up local inviting user (may be nil). policyEngine may be nil.
func NewHandler(
	outgoingRepo invitesoutgoing.OutgoingInviteRepo,
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

// HandleInviteAccepted handles POST /ocm/invite-accepted. Error table: F3=A.
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

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Warn("failed to read invite-accepted request body", "error", err)
		h.sendOCMError(w, http.StatusBadRequest, "INVALID_BODY")
		return
	}

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
	var req spec.InviteAcceptedRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Warn("failed to decode invite-accepted request", "error", err)
		h.sendOCMError(w, http.StatusBadRequest, "INVALID_BODY")
		return
	}

	if req.RecipientProvider == "" {
		h.sendOCMError(w, http.StatusBadRequest, "RECIPIENT_PROVIDER_REQUIRED")
		return
	}
	if strings.Contains(req.RecipientProvider, "://") {
		h.sendOCMError(w, http.StatusBadRequest, "INVALID_RECIPIENT_PROVIDER")
		return
	}
	if req.Token == "" {
		h.sendOCMError(w, http.StatusBadRequest, "TOKEN_REQUIRED")
		return
	}
	if req.UserID == "" {
		h.sendOCMError(w, http.StatusBadRequest, "USERID_REQUIRED")
		return
	}
	ctx := r.Context()
	invite, err := h.outgoingRepo.GetByToken(ctx, req.Token)
	if err != nil {
		log.Warn("invite-accepted for unknown token", "recipient_provider", req.RecipientProvider)
		h.sendOCMError(w, http.StatusBadRequest, "TOKEN_INVALID")
		return
	}
	if !invite.ExpiresAt.IsZero() && time.Now().After(invite.ExpiresAt) {
		h.sendOCMError(w, http.StatusBadRequest, "TOKEN_EXPIRED")
		return
	}
	if invite.Status == invites.InviteStatusAccepted {
		log.Info("duplicate invite-accepted", "recipient_provider", req.RecipientProvider)
		h.sendOCMError(w, http.StatusConflict, "INVITE_ALREADY_ACCEPTED")
		return
	}
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
	if h.policyEngine != nil {
		decision := h.policyEngine.Evaluate(ctx, normalizedRecipientProvider, peerIdentity != nil && peerIdentity.Authenticated)
		if !decision.Allowed {
			h.sendOCMError(w, http.StatusForbidden, "INVITE_RECEIVER_NOT_TRUSTED")
			return
		}
	}
	if err := h.outgoingRepo.UpdateStatus(ctx, invite.ID, invites.InviteStatusAccepted, req.RecipientProvider); err != nil {
		log.Error("failed to update invite status", "id", invite.ID, "error", err)
		h.sendOCMError(w, http.StatusInternalServerError, "UPDATE_FAILED")
		return
	}

	log.Info("invite accepted",
		"recipient_provider", req.RecipientProvider,
		"user_id", req.UserID)
	response := h.buildInviteAcceptedResponse(ctx, invite, log)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// buildInviteAcceptedResponse returns local inviting user identity. F5=A: empty CreatedByUserID -> placeholder.
func (h *Handler) buildInviteAcceptedResponse(ctx context.Context, invite *invitesoutgoing.OutgoingInvite, log *slog.Logger) spec.InviteAcceptedResponse {
	if invite.CreatedByUserID == "" {
		return spec.InviteAcceptedResponse{
			UserID: address.EncodeFederatedOpaqueID("unknown", h.providerFQDN),
			Email:  "",
			Name:   "",
		}
	}
	if h.partyRepo == nil {
		log.Error("partyRepo not available for invite-accepted local user lookup")
		return spec.InviteAcceptedResponse{
			UserID: address.EncodeFederatedOpaqueID("unknown", h.providerFQDN),
			Email:  "",
			Name:   "",
		}
	}

	localUser, err := h.partyRepo.Get(ctx, invite.CreatedByUserID)
	if err != nil {
		log.Error("failed to look up local inviting user",
			"created_by_user_id", invite.CreatedByUserID, "error", err)
		return spec.InviteAcceptedResponse{
			UserID: address.EncodeFederatedOpaqueID("unknown", h.providerFQDN),
			Email:  "",
			Name:   "",
		}
	}

	return spec.InviteAcceptedResponse{
		UserID: address.EncodeFederatedOpaqueID(localUser.ID, h.providerFQDN),
		Email:  localUser.Email,
		Name:   localUser.DisplayName,
	}
}

func (h *Handler) sendOCMError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"message": message,
	})
}
