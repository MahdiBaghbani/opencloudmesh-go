// Package incoming handles inbound OCM share creation (POST /ocm/shares).
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

// Handler handles incoming OCM share endpoints (POST /ocm/shares).
type Handler struct {
	repo                        sharesinbox.IncomingShareRepo
	partyRepo                   identity.PartyRepo
	policyEngine                *peertrust.PolicyEngine
	localProviderFQDNForCompare string
	localScheme                 string
	signatureInboundMode        string
	logger                      *slog.Logger
}

// NewHandler creates a new incoming shares handler.
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

// CreateShare handles POST /ocm/shares following the spec-aligned inbound flow.
func (h *Handler) CreateShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log := appctx.GetLogger(r.Context())

	// Parse request body
	var req spec.NewShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("failed to parse share request", "error", err)
		spec.WriteOCMError(w, http.StatusBadRequest, "INVALID_JSON")
		return
	}

	// Step 1: Compute strictPayloadValidation (per-peer strict vs lenient)
	peerIdentity := crypto.GetPeerIdentity(r.Context())
	strictPayloadValidation := h.signatureInboundMode == "strict"
	if h.signatureInboundMode == "lenient" {
		strictPayloadValidation = peerIdentity != nil && peerIdentity.Authenticated
	}

	// Step 2: Validate required fields (F1=A)
	validationErrs := spec.ValidateRequiredFields(&req)

	// protocol.name validation depends on strictPayloadValidation
	if strictPayloadValidation {
		if req.Protocol.Name == "" && (req.Protocol.WebDAV != nil || req.Protocol.WebApp != nil) {
			validationErrs = append(validationErrs, spec.ValidationError{Name: "protocol.name", Message: "REQUIRED"})
		}
	}
	// In lenient mode: missing protocol.name is allowed when protocol.webdav is present

	if len(validationErrs) > 0 {
		log.Warn("share validation failed", "errors", len(validationErrs))
		spec.WriteValidationError(w, "MISSING_REQUIRED_FIELDS", validationErrs)
		return
	}

	// Step 3: Validate owner and sender OCM address format (F2=A)
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

	// Step 4: Enforce protocol support (WebDAV only)
	if req.Protocol.WebDAV == nil {
		log.Warn("share rejected: no webdav protocol")
		spec.WriteProtocolNotSupported(w)
		return
	}

	// Determine effective protocol name
	effectiveProtocolName := req.Protocol.Name
	if effectiveProtocolName == "" && !strictPayloadValidation {
		effectiveProtocolName = "multi"
	}
	if effectiveProtocolName != "webdav" && effectiveProtocolName != "multi" {
		log.Warn("share rejected: unsupported protocol name", "protocol_name", effectiveProtocolName)
		spec.WriteProtocolNotSupported(w)
		return
	}

	// Extract sender host for policy check and storage
	senderHost := ExtractSenderHost(req.Sender)

	// Trust validation: check policy if policy engine is available
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

	// Step 5: Parse shareWith using last-@ semantics
	identifier, shareWithProvider, err := address.Parse(req.ShareWith)
	if err != nil {
		log.Warn("invalid shareWith format", "share_with", req.ShareWith, "error", err)
		spec.WriteValidationError(w, "INVALID_SHARE_WITH", []spec.ValidationError{
			{Name: "shareWith", Message: "INVALID_FORMAT"},
		})
		return
	}

	// Step 6: Provider match via hostport normalization
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

	// Step 7: Reject unsupported share types with 501; accept all resourceType values (F7=A)
	if req.ShareType != "user" {
		log.Warn("unsupported share type", "share_type", req.ShareType)
		spec.WriteShareTypeNotSupported(w)
		return
	}

	// Step 8: Resolve recipient identity (triple resolution)
	resolvedUser, err := h.resolveRecipient(r.Context(), identifier)
	if err != nil {
		log.Warn("recipient not found", "identifier", identifier)
		spec.WriteValidationError(w, "RECIPIENT_NOT_FOUND", []spec.ValidationError{
			{Name: "shareWith", Message: "NOT_FOUND"},
		})
		return
	}

	// Step 9: Duplicate check (E9, F10=A)
	existing, err := h.repo.GetByProviderID(r.Context(), senderHost, req.ProviderID)
	if err == nil && existing != nil {
		// Idempotent: return 200 with CreateShareResponse
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

	// Step 10: Build and store the inbox record
	share := &sharesinbox.IncomingShare{
		ProviderID:           req.ProviderID,
		SenderHost:           senderHost,
		Owner:                req.Owner,
		Sender:               req.Sender,
		ShareWith:            req.ShareWith, // raw, for audit/debug (Q1=A)
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

	// Handle WebDAV protocol details
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

	// Step 11: Return 201 with CreateShareResponse DTO (E4=A, E10=A)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(spec.CreateShareResponse{
		RecipientDisplayName: share.RecipientDisplayName,
	})
}

// resolveRecipient tries to find a local user by resolution order:
// 1. PartyRepo.Get(identifier) - canonical internal user id
// 2. PartyRepo.GetByUsername(identifier)
// 3. PartyRepo.GetByEmail(identifier) - repo normalizes email internally
// 4. Federated opaque ID decode fallback (gated, see plan D2/D3/D11)
func (h *Handler) resolveRecipient(ctx context.Context, identifier string) (*identity.User, error) {
	// Try by canonical ID first
	user, err := h.partyRepo.Get(ctx, identifier)
	if err == nil {
		return user, nil
	}

	// Try by username
	user, err = h.partyRepo.GetByUsername(ctx, identifier)
	if err == nil {
		return user, nil
	}

	// Try by email (repo handles normalization internally)
	user, err = h.partyRepo.GetByEmail(ctx, identifier)
	if err == nil {
		return user, nil
	}

	// Federated opaque ID decode fallback (gated).
	// Only fires when identifier has no '@' (prevents email false positives),
	// matches base64-like charset, decodes to userID@idp, and decoded idp
	// matches local provider after normalization.
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
