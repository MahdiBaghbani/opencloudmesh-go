// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// parseCreateShareRequest reads and validates the initial request envelope.
func (h *Handler) parseCreateShareRequest(
	w http.ResponseWriter,
	r *http.Request,
) (spec.NewShareRequest, map[string]json.RawMessage, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return spec.NewShareRequest{}, nil, false
	}

	log := appctx.GetLogger(r.Context())

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Warn("failed to read share request body", "error", err)
		spec.WriteOCMError(w, http.StatusBadRequest, "INVALID_JSON")

		return spec.NewShareRequest{}, nil, false
	}

	var rawFields map[string]json.RawMessage
	if err := json.Unmarshal(body, &rawFields); err != nil {
		log.Warn("failed to parse share request", "error", err)
		spec.WriteOCMError(w, http.StatusBadRequest, "INVALID_JSON")

		return spec.NewShareRequest{}, nil, false
	}

	var req spec.NewShareRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Warn("failed to decode share request", "error", err)
		spec.WriteOCMError(w, http.StatusBadRequest, "INVALID_JSON")

		return spec.NewShareRequest{}, nil, false
	}

	validationErrs := spec.ValidateRequiredFields(&req)
	if len(validationErrs) > 0 {
		log.Warn("share validation failed", "errors", len(validationErrs))
		spec.WriteValidationError(w, "MISSING_REQUIRED_FIELDS", validationErrs)

		return spec.NewShareRequest{}, nil, false
	}

	return req, rawFields, true
}

// validateProtocolAdmissions checks protocol shape, arms, and per-arm requirements.
func (h *Handler) validateProtocolAdmissions(
	w http.ResponseWriter,
	r *http.Request,
	req *spec.NewShareRequest,
	rawFields map[string]json.RawMessage,
	localRequires bool,
) bool {
	log := appctx.GetLogger(r.Context())

	if protocolRaw, ok := rawFields["protocol"]; ok {
		var protocolArms map[string]json.RawMessage
		if err := json.Unmarshal(protocolRaw, &protocolArms); err == nil {
			if err := spec.ValidateProtocolArms(protocolArms); err != nil {
				log.Warn("share rejected: unsupported protocol arm")
				spec.WriteProtocolNotSupported(w)

				return false
			}
		}
	}

	if shapeErr := spec.ValidateProtocolShape(req.Protocol); shapeErr != nil {
		if shapeErr.Message == validationUnsupported {
			log.Warn("share rejected: unsupported protocol shape", "field", shapeErr.Name)
			spec.WriteProtocolNotSupported(w)

			return false
		}

		spec.WriteValidationError(w, "INVALID_PROTOCOL", []spec.ValidationError{*shapeErr})

		return false
	}

	webdav := req.Protocol.WebDAV
	if webdav != nil {
		webdavErrs := spec.ValidateWebDAVProtocolWire(webdav)
		webdavErrs = append(webdavErrs, spec.ValidateWebDAVRequirementsAdmission(localRequires, webdav.Requirements)...)
		webdavErrs = dedupeValidationErrors(webdavErrs)

		if len(webdavErrs) > 0 {
			writeProtocolValidationErrors(w, webdavErrs)

			return false
		}
	}

	webapp := req.Protocol.Webapp
	if webapp != nil {
		webappErrs := spec.ValidateWebappProtocolWire(webapp)
		webappErrs = append(webappErrs, spec.ValidateWebappRequirementsAdmission(localRequires, webapp.Requirements)...)
		webappErrs = dedupeValidationErrors(webappErrs)

		if len(webappErrs) > 0 {
			writeProtocolValidationErrors(w, webappErrs)

			return false
		}

		log.Warn("share rejected: webapp protocol not supported")
		spec.WriteProtocolNotSupported(w)

		return false
	}

	return true
}

// resolveShareRecipient validates owner/sender formats, shareWith provider, and resolves the local recipient.
func (h *Handler) resolveShareRecipient(
	w http.ResponseWriter,
	r *http.Request,
	req *spec.NewShareRequest,
) (*identity.User, bool) {
	log := appctx.GetLogger(r.Context())

	var formatErrs []spec.ValidationError
	if _, _, err := address.Parse(req.Owner); err != nil {
		formatErrs = append(formatErrs, spec.ValidationError{Name: "owner", Message: validationInvalidFormat})
	}

	if _, _, err := address.Parse(req.Sender); err != nil {
		formatErrs = append(formatErrs, spec.ValidationError{Name: "sender", Message: validationInvalidFormat})
	}

	if len(formatErrs) > 0 {
		log.Warn("share owner/sender format invalid", "errors", len(formatErrs))
		spec.WriteValidationError(w, "INVALID_FIELD_FORMAT", formatErrs)

		return nil, false
	}

	identifier, shareWithProvider, err := address.Parse(req.ShareWith)
	if err != nil {
		log.Warn("invalid shareWith format", "share_with", req.ShareWith, "error", err)
		spec.WriteValidationError(w, "INVALID_SHARE_WITH", []spec.ValidationError{
			{Name: fieldShareWith, Message: validationInvalidFormat},
		})

		return nil, false
	}

	normalizedProvider, err := hostport.Normalize(shareWithProvider, h.localScheme)
	if err != nil {
		log.Warn("failed to normalize shareWith provider", "provider", shareWithProvider, "error", err)
		spec.WriteValidationError(w, "PROVIDER_MISMATCH", []spec.ValidationError{
			{Name: fieldShareWith, Message: "PROVIDER_MISMATCH"},
		})

		return nil, false
	}

	if !strings.EqualFold(normalizedProvider, h.localProviderFQDNForCompare) {
		log.Warn("provider mismatch",
			"share_with_provider", normalizedProvider,
			"local_provider", h.localProviderFQDNForCompare)
		spec.WriteValidationError(w, "PROVIDER_MISMATCH", []spec.ValidationError{
			{Name: fieldShareWith, Message: "PROVIDER_MISMATCH"},
		})

		return nil, false
	}

	resolvedUser, err := h.resolveRecipient(r.Context(), identifier)
	if err != nil {
		log.Warn("recipient not found", "identifier", identifier)
		spec.WriteValidationError(w, "RECIPIENT_NOT_FOUND", []spec.ValidationError{
			{Name: fieldShareWith, Message: "NOT_FOUND"},
		})

		return nil, false
	}

	if req.ShareType != "user" {
		log.Warn("unsupported share type", "share_type", req.ShareType)
		spec.WriteShareTypeNotSupported(w)

		return nil, false
	}

	if !spec.IsSupportedResourceType(req.ResourceType) {
		log.Warn("unsupported resource type", "resource_type", req.ResourceType)
		spec.WriteResourceTypeNotSupported(w)

		return nil, false
	}

	return resolvedUser, true
}

// authenticateSenderAndResolveOwner enforces peer policy and validates the owner provider against the peer identity.
func (h *Handler) authenticateSenderAndResolveOwner(
	w http.ResponseWriter,
	r *http.Request,
	req *spec.NewShareRequest,
) (string, string, bool) {
	log := appctx.GetLogger(r.Context())

	peerIdentity := inboundsignature.GetPeerIdentity(r.Context())
	authenticated := peerIdentity != nil && peerIdentity.Authenticated

	var senderHost string
	if authenticated {
		senderHost = peerIdentity.AuthorityForCompare
	} else {
		var hostErr error

		senderHost, hostErr = address.NormalizedProviderFrom(req.Sender, h.localScheme)
		if hostErr != nil {
			log.Warn("failed to normalize sender provider", "error", hostErr)
			spec.WriteOCMError(w, http.StatusForbidden, "UNTRUSTED_PROVIDER")

			return "", "", false
		}
	}

	if h.policyEngine != nil {
		decision := h.policyEngine.Evaluate(r.Context(), senderHost, authenticated)
		if !decision.Allowed {
			log.Warn("share rejected by policy",
				"sender", senderHost,
				"reason", decision.Reason,
				"authenticated", authenticated)

			translated := reason.TranslatePolicyCode(decision.ReasonCode)
			if translated == "" {
				translated = "SENDER_NOT_AUTHORIZED"
			}

			spec.WriteOCMError(w, reason.OCMStatus(translated), translated)

			return "", "", false
		}
	}

	ownerHost, err := address.NormalizedProviderFrom(req.Owner, h.localScheme)
	if err != nil {
		log.Warn("failed to normalize owner provider", "error", err)
		spec.WriteOCMError(w, http.StatusForbidden, "UNTRUSTED_PROVIDER")

		return "", "", false
	}

	if peerIdentity != nil && peerIdentity.Authenticated {
		if peerIdentity.AuthorityForCompare != ownerHost {
			log.Warn("share owner provider mismatch",
				"signature_authority", peerIdentity.AuthorityForCompare,
				"owner_provider", ownerHost)
			spec.WriteOCMError(w, http.StatusForbidden, "UNTRUSTED_PROVIDER")

			return "", "", false
		}
	}

	return senderHost, ownerHost, true
}

// gateMustInvite enforces the exchanged-invite requirement for inbound share
// creation when enforcement is enabled. It is separate from the peer-trust
// PolicyEngine and independent of peer trust: an exact host PLUS user match
// against an exchanged invite is required, checked bidirectionally (the remote
// sender either invited the local recipient, or accepted the local recipient's
// invite). There is no host-only fallback in enforced mode; the explicit
// opt-out retains legacy acceptance.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L763-L765
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L1303-L1307
func (h *Handler) gateMustInvite(
	w http.ResponseWriter,
	r *http.Request,
	req *spec.NewShareRequest,
	resolvedUser *identity.User,
) bool {
	if !h.mustInviteEnforced {
		return true
	}

	log := appctx.GetLogger(r.Context())

	if h.incomingInviteRepo == nil || h.outgoingInviteRepo == nil {
		log.Error("must-invite enforced but invite repositories are not wired")
		spec.WriteOCMError(w, reason.OCMStatus(reason.StorageError), reason.StorageError)

		return false
	}

	senderUserID, senderProvider, err := address.Parse(req.Sender)
	if err != nil {
		log.Warn("must-invite: malformed sender", "error", err)
		spec.WriteOCMError(w, reason.OCMStatus(reason.SenderNotTrusted), reason.SenderNotTrusted)

		return false
	}

	senderHostNormalized, err := hostport.Normalize(senderProvider, h.localScheme)
	if err != nil {
		log.Warn("must-invite: failed to normalize sender provider",
			"sender_provider", senderProvider, "error", err)
		spec.WriteOCMError(w, reason.OCMStatus(reason.SenderNotTrusted), reason.SenderNotTrusted)

		return false
	}

	// Anti-spoof: an authenticated peer's signature authority must match the
	// normalized body sender provider; on match the invite lookup uses the
	// authenticated normalized authority.
	if peerIdentity := inboundsignature.GetPeerIdentity(r.Context()); peerIdentity != nil && peerIdentity.Authenticated {
		if peerIdentity.AuthorityForCompare != senderHostNormalized {
			log.Warn("must-invite: sender host mismatch",
				"signature_authority", peerIdentity.AuthorityForCompare,
				"sender_provider", senderProvider)
			spec.WriteOCMError(w, reason.OCMStatus(reason.SenderNotTrusted), reason.SenderNotTrusted)

			return false
		}

		senderHostNormalized = peerIdentity.AuthorityForCompare
	}

	// Direction 1: the remote sender invited the local recipient and the
	// recipient accepted (incoming invite).
	_, err = h.incomingInviteRepo.FindAcceptedForSender(r.Context(), resolvedUser.ID, senderUserID, senderHostNormalized)
	if err == nil {
		return true
	}

	if !errors.Is(err, invites.ErrInviteNotFound) {
		log.Error("must-invite: incoming invite lookup failed", "error", err)
		spec.WriteOCMError(w, reason.OCMStatus(reason.StorageError), reason.StorageError)

		return false
	}

	// Direction 2: the local recipient invited the remote sender and the
	// sender accepted (outgoing invite).
	_, err = h.outgoingInviteRepo.FindAcceptedForRecipient(r.Context(), resolvedUser.ID, senderUserID, senderHostNormalized)
	if err == nil {
		return true
	}

	if !errors.Is(err, invites.ErrInviteNotFound) {
		log.Error("must-invite: outgoing invite lookup failed", "error", err)
		spec.WriteOCMError(w, reason.OCMStatus(reason.StorageError), reason.StorageError)

		return false
	}

	log.Warn("must-invite: no exchanged invite for sender",
		"sender_user_id", senderUserID,
		"sender_host", senderHostNormalized,
		"recipient_user_id", resolvedUser.ID)
	spec.WriteOCMError(w, reason.OCMStatus(reason.SenderNotTrusted), reason.SenderNotTrusted)

	return false
}

// storeIncomingShare returns an existing duplicate or persists a new share and writes the response.
func (h *Handler) storeIncomingShare(
	w http.ResponseWriter,
	r *http.Request,
	req *spec.NewShareRequest,
	senderHost,
	ownerHost string,
	resolvedUser *identity.User,
) {
	log := appctx.GetLogger(r.Context())

	existing, err := h.repo.GetByProviderID(r.Context(), senderHost, req.ProviderID)
	if err != nil && !errors.Is(err, ErrShareNotFound) {
		log.Error("failed to look up incoming share by provider key", "error", err)
		spec.WriteOCMError(w, reason.OCMStatus(reason.StorageError), reason.StorageError)

		return
	}

	if existing != nil {
		log.Info("duplicate share, returning existing",
			"provider_id", req.ProviderID,
			"sender", senderHost)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(spec.CreateShareResponse{
			RecipientDisplayName: resolvedUser.DisplayName,
		}); err != nil {
			log.Error("failed to encode share response", "error", err)
		}

		return
	}

	webdav := req.Protocol.WebDAV

	var (
		webdavURI, webdavSharedSecret         string
		webdavPermissions, webdavRequirements []string
	)

	if webdav != nil {
		webdavURI = webdav.URI
		webdavSharedSecret = webdav.SharedSecret
		webdavPermissions = webdav.Permissions
		webdavRequirements = append([]string(nil), webdav.Requirements...)
	}

	share := &IncomingShare{
		ProviderID:           req.ProviderID,
		SenderHost:           senderHost,
		OwnerHost:            ownerHost,
		Owner:                req.Owner,
		Sender:               req.Sender,
		ShareWith:            req.ShareWith,
		Name:                 req.Name,
		Description:          req.Description,
		ResourceType:         req.ResourceType,
		ShareType:            req.ShareType,
		OwnerDisplayName:     req.OwnerDisplayName,
		SenderDisplayName:    req.SenderDisplayName,
		Expiration:           req.Expiration,
		Status:               shares.ShareStatusPending,
		RecipientUserID:      resolvedUser.ID,
		RecipientDisplayName: resolvedUser.DisplayName,
		WebDAVID:             webdavURI,
		SharedSecret:         webdavSharedSecret,
		Permissions:          webdavPermissions,
		Requirements:         webdavRequirements,
	}
	share.ProtocolName = req.Protocol.Name

	if err := h.repo.Create(r.Context(), share); err != nil {
		log.Error("failed to store share", "error", err)
		spec.WriteOCMError(w, reason.OCMStatus(reason.StorageError), reason.StorageError)

		return
	}

	log.Info("share created",
		"share_id", share.ShareID,
		"provider_id", share.ProviderID,
		"sender", senderHost,
		"recipient_user_id", share.RecipientUserID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(spec.CreateShareResponse{
		RecipientDisplayName: share.RecipientDisplayName,
	}); err != nil {
		log.Error("failed to encode share response", "error", err)
	}
}
