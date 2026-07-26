// Package incoming handles POST /ocm/shares. Resolves recipient by canonical ID, username, then email; provider via hostport.Normalize.
package incoming

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

type Handler struct {
	repo                        sharesinbox.IncomingShareRepo
	partyRepo                   identity.PartyRepo
	policyEngine                *peertrust.PolicyEngine
	resolver                    *policy.PeerMappingResolver
	localProviderFQDNForCompare string
	localScheme                 string
}

func NewHandler(
	repo sharesinbox.IncomingShareRepo,
	partyRepo identity.PartyRepo,
	policyEngine *peertrust.PolicyEngine,
	localProviderFQDNForCompare string,
	localScheme string,
	resolver *policy.PeerMappingResolver,
) *Handler {
	return &Handler{
		repo:                        repo,
		partyRepo:                   partyRepo,
		policyEngine:                policyEngine,
		resolver:                    resolver,
		localProviderFQDNForCompare: localProviderFQDNForCompare,
		localScheme:                 localScheme,
	}
}

func (h *Handler) CreateShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log := appctx.GetLogger(r.Context())

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Warn("failed to read share request body", "error", err)
		spec.WriteOCMError(w, http.StatusBadRequest, "INVALID_JSON")

		return
	}

	var rawFields map[string]json.RawMessage
	if err := json.Unmarshal(body, &rawFields); err != nil {
		log.Warn("failed to parse share request", "error", err)
		spec.WriteOCMError(w, http.StatusBadRequest, "INVALID_JSON")

		return
	}

	var req spec.NewShareRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Warn("failed to decode share request", "error", err)
		spec.WriteOCMError(w, http.StatusBadRequest, "INVALID_JSON")

		return
	}

	validationErrs := spec.ValidateRequiredFields(&req)
	if len(validationErrs) > 0 {
		log.Warn("share validation failed", "errors", len(validationErrs))
		spec.WriteValidationError(w, "MISSING_REQUIRED_FIELDS", validationErrs)

		return
	}

	if protocolRaw, ok := rawFields["protocol"]; ok {
		var protocolArms map[string]json.RawMessage
		if err := json.Unmarshal(protocolRaw, &protocolArms); err == nil {
			if err := spec.ValidateProtocolArms(protocolArms); err != nil {
				log.Warn("share rejected: unsupported protocol arm")
				spec.WriteProtocolNotSupported(w)

				return
			}
		}
	}

	if shapeErr := spec.ValidateProtocolShape(req.Protocol); shapeErr != nil {
		if shapeErr.Message == "UNSUPPORTED" {
			log.Warn("share rejected: unsupported protocol shape", "field", shapeErr.Name)
			spec.WriteProtocolNotSupported(w)

			return
		}

		spec.WriteValidationError(w, "INVALID_PROTOCOL", []spec.ValidationError{*shapeErr})

		return
	}
	// localRequires defaults to strict; a non-nil resolver lets peer mapping relax it.
	localRequires := true

	if h.resolver != nil {
		if _, senderHost, err := address.Parse(req.Sender); err == nil {
			localRequires = h.resolver.ResolveFacts(senderHost).RequiresTokenExchange
		}
	}

	webdav := req.Protocol.WebDAV
	if webdav != nil {
		webdavErrs := spec.ValidateWebDAVProtocolWire(webdav)
		webdavErrs = append(webdavErrs, spec.ValidateWebDAVRequirementsAdmission(localRequires, webdav.Requirements)...)

		webdavErrs = dedupeValidationErrors(webdavErrs)
		if len(webdavErrs) > 0 {
			writeProtocolValidationErrors(w, webdavErrs)
			return
		}
	}

	webapp := req.Protocol.Webapp
	if webapp != nil {
		webappErrs := spec.ValidateWebappProtocolWire(webapp)
		webappErrs = append(webappErrs, spec.ValidateWebappRequirementsAdmission(localRequires, webapp.Requirements)...)

		webappErrs = dedupeValidationErrors(webappErrs)
		if len(webappErrs) > 0 {
			writeProtocolValidationErrors(w, webappErrs)
			return
		}
		// ocmgo does not advertise webapp-receive; reject inbound webapp arms
		// at admit time with 501 (protocol not supported) instead of falsely
		// returning 201.
		log.Warn("share rejected: webapp protocol not supported")
		spec.WriteProtocolNotSupported(w)

		return
	}

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

		return
	}

	identifier, shareWithProvider, err := address.Parse(req.ShareWith)
	if err != nil {
		log.Warn("invalid shareWith format", "share_with", req.ShareWith, "error", err)
		spec.WriteValidationError(w, "INVALID_SHARE_WITH", []spec.ValidationError{
			{Name: "shareWith", Message: "INVALID_FORMAT"},
		})

		return
	}

	normalizedProvider, err := hostport.Normalize(shareWithProvider, h.localScheme)
	if err != nil {
		log.Warn("failed to normalize shareWith provider", "provider", shareWithProvider, "error", err)
		spec.WriteValidationError(w, "PROVIDER_MISMATCH", []spec.ValidationError{
			{Name: "shareWith", Message: "PROVIDER_MISMATCH"},
		})

		return
	}

	if !strings.EqualFold(normalizedProvider, h.localProviderFQDNForCompare) {
		log.Warn("provider mismatch",
			"share_with_provider", normalizedProvider,
			"local_provider", h.localProviderFQDNForCompare)
		spec.WriteValidationError(w, "PROVIDER_MISMATCH", []spec.ValidationError{
			{Name: "shareWith", Message: "PROVIDER_MISMATCH"},
		})

		return
	}

	resolvedUser, err := h.resolveRecipient(r.Context(), identifier)
	if err != nil {
		log.Warn("recipient not found", "identifier", identifier)
		spec.WriteValidationError(w, "RECIPIENT_NOT_FOUND", []spec.ValidationError{
			{Name: "shareWith", Message: "NOT_FOUND"},
		})

		return
	}

	if req.ShareType != "user" {
		log.Warn("unsupported share type", "share_type", req.ShareType)
		spec.WriteShareTypeNotSupported(w)

		return
	}

	if !spec.IsSupportedResourceType(req.ResourceType) {
		log.Warn("unsupported resource type", "resource_type", req.ResourceType)
		spec.WriteResourceTypeNotSupported(w)

		return
	}

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

			return
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

			return
		}

		if peerIdentity.AuthorityForCompare != normalizedOwnerProvider {
			log.Warn("share owner provider mismatch",
				"signature_authority", peerIdentity.AuthorityForCompare,
				"owner_provider", ownerProvider)
			spec.WriteOCMError(w, http.StatusForbidden, "UNTRUSTED_PROVIDER")

			return
		}
	}

	existing, err := h.repo.GetByProviderID(r.Context(), senderHost, req.ProviderID)
	if err == nil && existing != nil {
		log.Info("duplicate share, returning existing",
			"provider_id", req.ProviderID,
			"sender", senderHost)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(spec.CreateShareResponse{
			RecipientDisplayName: existing.RecipientDisplayName,
		})

		return
	}

	webdav = req.Protocol.WebDAV
	// Persist fields from each protocol arm when present.
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
	json.NewEncoder(w).Encode(spec.CreateShareResponse{
		RecipientDisplayName: share.RecipientDisplayName,
	})
}

func dedupeValidationErrors(errs []spec.ValidationError) []spec.ValidationError {
	if len(errs) == 0 {
		return errs
	}

	seen := make(map[string]struct{}, len(errs))

	out := make([]spec.ValidationError, 0, len(errs))
	for _, e := range errs {
		key := e.Name + "\x00" + e.Message
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}

		out = append(out, e)
	}

	return out
}

// writeProtocolValidationErrors maps spec protocol validation errors to the
// shared OCM response taxonomy used by both the webdav and webapp arms: any
// UNSUPPORTED value yields PROTOCOL_NOT_SUPPORTED (501); all other errors
// (missing/invalid required fields, including must-use-mfa hard-rejects) yield
// INVALID_PROTOCOL
// (400) with the validation errors attached so the rejection is observable.
func writeProtocolValidationErrors(w http.ResponseWriter, errs []spec.ValidationError) {
	for _, e := range errs {
		if e.Message == "UNSUPPORTED" {
			spec.WriteProtocolNotSupported(w)
			return
		}
	}

	spec.WriteValidationError(w, "INVALID_PROTOCOL", errs)
}

// resolveRecipient: canonical ID -> username -> email -> federated opaque ID (if no @, base64-like, idp matches).
func (h *Handler) resolveRecipient(ctx context.Context, identifier string) (*identity.User, error) {
	user, err := h.partyRepo.Get(ctx, identifier)
	if err == nil {
		return user, nil
	}

	user, err = h.partyRepo.GetByUsername(ctx, identifier)
	if err == nil {
		return user, nil
	}

	user, err = h.partyRepo.GetByEmail(ctx, identifier)
	if err == nil {
		return user, nil
	}

	if !strings.Contains(identifier, "@") && address.LooksLikeBase64(identifier) {
		decodedUserID, decodedIDP, ok := address.DecodeFederatedOpaqueID(identifier)
		if ok {
			normalizedIDP, normErr := hostport.Normalize(decodedIDP, h.localScheme)
			if normErr == nil && strings.EqualFold(normalizedIDP, h.localProviderFQDNForCompare) {
				user, err := h.partyRepo.Get(ctx, decodedUserID)
				if err == nil {
					return user, nil
				}
			}
		}
	}

	return nil, errors.New("recipient not found")
}

func ExtractSenderHost(sender string) string {
	_, provider, err := address.Parse(sender)
	if err != nil {
		return ""
	}

	return strings.ToLower(provider)
}
