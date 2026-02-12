// Package incoming handles POST /ocm/shares. Resolves recipient by canonical ID, username, then email; provider via hostport.Normalize.
package incoming

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

type Handler struct {
	repo                        sharesinbox.IncomingShareRepo
	partyRepo                   identity.PartyRepo
	policyEngine                *peertrust.PolicyEngine
	localProviderFQDNForCompare string
	localScheme                 string
	signatureInboundMode        string
	logger                      *slog.Logger
}

func NewHandler(
	repo sharesinbox.IncomingShareRepo,
	partyRepo identity.PartyRepo,
	policyEngine *peertrust.PolicyEngine,
	localProviderFQDNForCompare string,
	localScheme string,
	inboundMode string,
	logger *slog.Logger,
) *Handler {
	logger = logutil.NoopIfNil(logger)
	return &Handler{
		repo:                        repo,
		partyRepo:                   partyRepo,
		policyEngine:                policyEngine,
		localProviderFQDNForCompare: localProviderFQDNForCompare,
		localScheme:                 localScheme,
		signatureInboundMode:        inboundMode,
		logger:                      logger,
	}
}

func (h *Handler) CreateShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log := appctx.GetLogger(r.Context())
	var req spec.NewShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("failed to parse share request", "error", err)
		spec.WriteOCMError(w, http.StatusBadRequest, "INVALID_JSON")
		return
	}
	peerIdentity := crypto.GetPeerIdentity(r.Context())
	strictPayloadValidation := h.signatureInboundMode == "strict"
	if h.signatureInboundMode == "lenient" {
		strictPayloadValidation = peerIdentity != nil && peerIdentity.Authenticated
	}
	validationErrs := spec.ValidateRequiredFields(&req)
	if strictPayloadValidation {
		if req.Protocol.Name == "" && (req.Protocol.WebDAV != nil || req.Protocol.WebApp != nil) {
			validationErrs = append(validationErrs, spec.ValidationError{Name: "protocol.name", Message: "REQUIRED"})
		}
	}
	if len(validationErrs) > 0 {
		log.Warn("share validation failed", "errors", len(validationErrs))
		spec.WriteValidationError(w, "MISSING_REQUIRED_FIELDS", validationErrs)
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
	if req.Protocol.WebDAV == nil {
		log.Warn("share rejected: no webdav protocol")
		spec.WriteProtocolNotSupported(w)
		return
	}
	effectiveProtocolName := req.Protocol.Name
	if effectiveProtocolName == "" && !strictPayloadValidation {
		effectiveProtocolName = "multi"
	}
	if effectiveProtocolName != "webdav" && effectiveProtocolName != "multi" {
		log.Warn("share rejected: unsupported protocol name", "protocol_name", effectiveProtocolName)
		spec.WriteProtocolNotSupported(w)
		return
	}
	senderHost := ExtractSenderHost(req.Sender)
	if h.policyEngine != nil {
		authenticated := peerIdentity != nil && peerIdentity.Authenticated
		decision := h.policyEngine.Evaluate(r.Context(), senderHost, authenticated)
		if !decision.Allowed {
			log.Warn("share rejected by policy",
				"sender", senderHost,
				"reason", decision.Reason,
				"authenticated", authenticated)
			msg := decision.ReasonCode
			if msg == "" {
				msg = "SENDER_NOT_AUTHORIZED"
			}
			spec.WriteOCMError(w, http.StatusForbidden, msg)
			return
		}
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
	if req.ShareType != "user" {
		log.Warn("unsupported share type", "share_type", req.ShareType)
		spec.WriteShareTypeNotSupported(w)
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
	share := &sharesinbox.IncomingShare{
		ProviderID:           req.ProviderID,
		SenderHost:           senderHost,
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
	}
	if req.Protocol.WebDAV != nil {
		webdav := req.Protocol.WebDAV
		if IsAbsoluteURI(webdav.URI) {
			share.WebDAVURIAbsolute = webdav.URI
		} else {
			share.WebDAVID = webdav.URI
		}
		share.SharedSecret = webdav.SharedSecret
		share.Permissions = webdav.Permissions

		if webdav.HasRequirement(spec.RequirementMustExchangeToken) {
			share.MustExchangeToken = true
		}
	}

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
