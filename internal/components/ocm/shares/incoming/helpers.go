package incoming

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
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
		if shapeErr.Message == "UNSUPPORTED" {
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
		formatErrs = append(formatErrs, spec.ValidationError{Name: "owner", Message: "INVALID_FORMAT"})
	}

	if _, _, err := address.Parse(req.Sender); err != nil {
		formatErrs = append(formatErrs, spec.ValidationError{Name: "sender", Message: "INVALID_FORMAT"})
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
			{Name: "shareWith", Message: "INVALID_FORMAT"},
		})

		return nil, false
	}

	normalizedProvider, err := hostport.Normalize(shareWithProvider, h.localScheme)
	if err != nil {
		log.Warn("failed to normalize shareWith provider", "provider", shareWithProvider, "error", err)
		spec.WriteValidationError(w, "PROVIDER_MISMATCH", []spec.ValidationError{
			{Name: "shareWith", Message: "PROVIDER_MISMATCH"},
		})

		return nil, false
	}

	if !strings.EqualFold(normalizedProvider, h.localProviderFQDNForCompare) {
		log.Warn("provider mismatch",
			"share_with_provider", normalizedProvider,
			"local_provider", h.localProviderFQDNForCompare)
		spec.WriteValidationError(w, "PROVIDER_MISMATCH", []spec.ValidationError{
			{Name: "shareWith", Message: "PROVIDER_MISMATCH"},
		})

		return nil, false
	}

	resolvedUser, err := h.resolveRecipient(r.Context(), identifier)
	if err != nil {
		log.Warn("recipient not found", "identifier", identifier)
		spec.WriteValidationError(w, "RECIPIENT_NOT_FOUND", []spec.ValidationError{
			{Name: "shareWith", Message: "NOT_FOUND"},
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

	senderHost := ExtractSenderHost(req.Sender)
	if peerIdentity != nil && peerIdentity.Authenticated {
		senderHost = peerIdentity.AuthorityForCompare
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

	ownerHost := ""

	ownerProvider := ""
	if _, parsedOwnerProvider, err := address.Parse(req.Owner); err == nil {
		ownerProvider = parsedOwnerProvider
		ownerHost = ownerProvider
	}

	if ownerHost == "" {
		ownerHost = senderHost
	}

	if peerIdentity != nil && peerIdentity.Authenticated {
		normalizedOwnerProvider, err := hostport.Normalize(ownerProvider, h.localScheme)
		if err != nil {
			log.Warn("failed to normalize owner provider",
				"owner_provider", ownerProvider, "error", err)
			spec.WriteOCMError(w, http.StatusForbidden, "UNTRUSTED_PROVIDER")

			return "", "", false
		}

		if peerIdentity.AuthorityForCompare != normalizedOwnerProvider {
			log.Warn("share owner provider mismatch",
				"signature_authority", peerIdentity.AuthorityForCompare,
				"owner_provider", ownerProvider)
			spec.WriteOCMError(w, http.StatusForbidden, "UNTRUSTED_PROVIDER")

			return "", "", false
		}
	}

	return senderHost, ownerHost, true
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
	if err == nil && existing != nil {
		log.Info("duplicate share, returning existing",
			"provider_id", req.ProviderID,
			"sender", senderHost)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(spec.CreateShareResponse{
			RecipientDisplayName: existing.RecipientDisplayName,
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

	share := &sharesinbox.IncomingShare{
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
		Status:               sharesinbox.ShareStatusPending,
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
		spec.WriteOCMError(w, http.StatusInternalServerError, "STORAGE_ERROR")

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
