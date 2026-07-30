// Package incoming handles POST /ocm/invite-accepted.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md?plain=1#invite-acceptance-request-details
package incoming

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// Handler serves POST /ocm/invite-accepted with outgoing invite lookup and peer-trust gating.
type Handler struct {
	outgoingRepo invitesoutgoing.OutgoingInviteRepo
	partyRepo    identity.PartyRepo
	policyEngine *peertrust.PolicyEngine // may be nil when peer trust is disabled
	providerFQDN string
	localScheme  string // scheme from PublicOrigin for comparison normalization
}

// NewHandler creates the invite-accepted handler. partyRepo is required.
// policyEngine may be nil when peer trust is disabled.
func NewHandler(
	outgoingRepo invitesoutgoing.OutgoingInviteRepo,
	partyRepo identity.PartyRepo,
	policyEngine *peertrust.PolicyEngine,
	localProviderDomain string,
	localScheme string,
) *Handler {
	if partyRepo == nil {
		panic("incoming invite handler: partyRepo is required")
	}

	return &Handler{
		outgoingRepo: outgoingRepo,
		partyRepo:    partyRepo,
		policyEngine: policyEngine,
		providerFQDN: localProviderDomain,
		localScheme:  localScheme,
	}
}

// HandleInviteAccepted handles POST /ocm/invite-accepted.
// The mounted signature middleware enforces verify-if-present (rule 3) and
// unsigned-admission gating (rule 4, conditional on must-use-http-sig), so
// this handler proceeds only after admission.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L808-L823
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L440-L444
func (h *Handler) HandleInviteAccepted(w http.ResponseWriter, r *http.Request) {
	req, ok := h.parseInviteAcceptedRequest(w, r)
	if !ok {
		return
	}

	invite, ok := h.lookupAndValidateInvite(w, r, req)
	if !ok {
		return
	}

	if !h.verifyInviteSenderAndPolicy(w, r, req) {
		return
	}

	log := appctx.GetLogger(r.Context())

	response, ok := h.buildInviteAcceptedResponse(r.Context(), invite, log)
	if !ok {
		h.sendOCMError(w, http.StatusInternalServerError, "INVITER_IDENTITY_UNAVAILABLE")

		return
	}

	if err := h.outgoingRepo.UpdateStatus(r.Context(), invite.ID, invites.InviteStatusAccepted, req.RecipientProvider); err != nil {
		log.Error("failed to update invite status", "id", invite.ID, "error", err)
		h.sendOCMError(w, http.StatusInternalServerError, "UPDATE_FAILED")

		return
	}

	log.Info("invite accepted",
		"recipient_provider", req.RecipientProvider,
		"user_id", req.UserID)

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error("failed to encode invite accepted response", "error", err)
	}
}

func (h *Handler) buildInviteAcceptedResponse(
	ctx context.Context,
	invite *invitesoutgoing.OutgoingInvite,
	log *slog.Logger,
) (spec.InviteAcceptedResponse, bool) {
	if invite.CreatedByUserID == "" {
		log.Error("invite-accepted missing local inviting user id", "invite_id", invite.ID)

		return spec.InviteAcceptedResponse{}, false
	}

	localUser, err := h.partyRepo.Get(ctx, invite.CreatedByUserID)
	if err != nil {
		log.Error("failed to look up local inviting user",
			"created_by_user_id", invite.CreatedByUserID, "error", err)

		return spec.InviteAcceptedResponse{}, false
	}

	return spec.InviteAcceptedResponse{
		UserID: address.EncodeFederatedOpaqueID(localUser.ID, h.providerFQDN),
		Email:  localUser.Email,
		Name:   localUser.DisplayName,
	}, true
}

func (h *Handler) sendOCMError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:errcheck,errchkjson // response already started; write error cannot be recovered; payload marshals to fixed JSON, so encode failure is always nil in practice
	json.NewEncoder(w).Encode(map[string]string{
		"message": message,
	})
}

func (h *Handler) parseInviteAcceptedRequest(w http.ResponseWriter, r *http.Request) (spec.InviteAcceptedRequest, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return spec.InviteAcceptedRequest{}, false
	}

	log := appctx.GetLogger(r.Context())

	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		h.sendOCMError(w, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE")

		return spec.InviteAcceptedRequest{}, false
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Warn("failed to read invite-accepted request body", "error", err)
		h.sendOCMError(w, http.StatusBadRequest, "INVALID_BODY")

		return spec.InviteAcceptedRequest{}, false
	}

	var rawFields map[string]json.RawMessage
	if err := json.Unmarshal(body, &rawFields); err != nil {
		log.Warn("failed to parse invite-accepted request", "error", err)
		h.sendOCMError(w, http.StatusBadRequest, "INVALID_BODY")

		return spec.InviteAcceptedRequest{}, false
	}

	if _, ok := rawFields["email"]; !ok {
		h.sendOCMError(w, http.StatusBadRequest, "EMAIL_REQUIRED")

		return spec.InviteAcceptedRequest{}, false
	}

	if _, ok := rawFields["name"]; !ok {
		h.sendOCMError(w, http.StatusBadRequest, "NAME_REQUIRED")

		return spec.InviteAcceptedRequest{}, false
	}

	var req spec.InviteAcceptedRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Warn("failed to decode invite-accepted request", "error", err)
		h.sendOCMError(w, http.StatusBadRequest, "INVALID_BODY")

		return spec.InviteAcceptedRequest{}, false
	}

	if req.RecipientProvider == "" {
		h.sendOCMError(w, http.StatusBadRequest, "RECIPIENT_PROVIDER_REQUIRED")

		return spec.InviteAcceptedRequest{}, false
	}

	if strings.Contains(req.RecipientProvider, "://") {
		h.sendOCMError(w, http.StatusBadRequest, "INVALID_RECIPIENT_PROVIDER")

		return spec.InviteAcceptedRequest{}, false
	}

	if req.Token == "" {
		h.sendOCMError(w, http.StatusBadRequest, "TOKEN_REQUIRED")

		return spec.InviteAcceptedRequest{}, false
	}

	if req.UserID == "" {
		h.sendOCMError(w, http.StatusBadRequest, "USERID_REQUIRED")

		return spec.InviteAcceptedRequest{}, false
	}

	return req, true
}

func (h *Handler) lookupAndValidateInvite(w http.ResponseWriter, r *http.Request, req spec.InviteAcceptedRequest) (*invitesoutgoing.OutgoingInvite, bool) {
	log := appctx.GetLogger(r.Context())
	ctx := r.Context()

	invite, err := h.outgoingRepo.GetByToken(ctx, req.Token)
	if err != nil {
		log.Warn("invite-accepted for unknown token", "recipient_provider", req.RecipientProvider)
		h.sendOCMError(w, http.StatusBadRequest, "TOKEN_INVALID")

		return nil, false
	}

	if !invite.ExpiresAt.IsZero() && time.Now().After(invite.ExpiresAt) {
		h.sendOCMError(w, http.StatusBadRequest, "TOKEN_EXPIRED")

		return nil, false
	}

	if invite.Status == invites.InviteStatusAccepted {
		log.Info("duplicate invite-accepted", "recipient_provider", req.RecipientProvider)
		h.sendOCMError(w, http.StatusConflict, "INVITE_ALREADY_ACCEPTED")

		return nil, false
	}

	return invite, true
}

func (h *Handler) verifyInviteSenderAndPolicy(w http.ResponseWriter, r *http.Request, req spec.InviteAcceptedRequest) bool {
	log := appctx.GetLogger(r.Context())
	ctx := r.Context()

	peerIdentity := inboundsignature.GetPeerIdentity(ctx)

	normalizedRecipientProvider := req.RecipientProvider
	if peerIdentity != nil && peerIdentity.Authenticated {
		normalizedRecipient, err := hostport.Normalize(req.RecipientProvider, h.localScheme)
		if err != nil {
			log.Warn("failed to normalize recipient provider",
				"recipient_provider", req.RecipientProvider, "error", err)
			h.sendOCMError(w, http.StatusForbidden, "UNTRUSTED_PROVIDER")

			return false
		}

		normalizedRecipientProvider = normalizedRecipient
		if peerIdentity.AuthorityForCompare != normalizedRecipient {
			log.Warn("invite-accepted sender mismatch",
				"signature_authority", peerIdentity.AuthorityForCompare,
				"recipient_provider", req.RecipientProvider)
			h.sendOCMError(w, http.StatusForbidden, "UNTRUSTED_PROVIDER")

			return false
		}
	}

	if h.policyEngine != nil {
		decision := h.policyEngine.Evaluate(ctx, normalizedRecipientProvider, peerIdentity != nil && peerIdentity.Authenticated)
		if !decision.Allowed {
			h.sendOCMError(w, http.StatusForbidden, "INVITE_RECEIVER_NOT_TRUSTED")

			return false
		}
	}

	return true
}
