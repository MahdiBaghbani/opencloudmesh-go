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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// Handler handles incoming OCM share endpoints (POST /ocm/shares).
type Handler struct {
	repo                        shares.IncomingShareRepo
	partyRepo                   identity.PartyRepo
	policyEngine                *peertrust.PolicyEngine
	localProviderFQDNForCompare string
	localScheme                 string
	signatureInboundMode        string
	logger                      *slog.Logger
}

// NewHandler creates a new incoming shares handler.
func NewHandler(
	repo shares.IncomingShareRepo,
	partyRepo identity.PartyRepo,
	policyEngine *peertrust.PolicyEngine,
	localProviderFQDNForCompare string,
	localScheme string,
	inboundMode string,
	logger *slog.Logger,
) *Handler {
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
	var req shares.NewShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("failed to parse share request", "error", err)
		writeOCMError(w, http.StatusBadRequest, "INVALID_JSON")
		return
	}

	// Step 1: Compute strictPayloadValidation (per-peer strict vs lenient)
	peerIdentity := crypto.GetPeerIdentity(r.Context())
	strictPayloadValidation := h.signatureInboundMode == "strict"
	if h.signatureInboundMode == "lenient" {
		strictPayloadValidation = peerIdentity != nil && peerIdentity.Authenticated
	}

	// Step 2: Validate required fields (F1=A)
	validationErrs := ValidateRequiredFields(&req)

	// protocol.name validation depends on strictPayloadValidation
	if strictPayloadValidation {
		if req.Protocol.Name == "" && (req.Protocol.WebDAV != nil || req.Protocol.WebApp != nil) {
			validationErrs = append(validationErrs, ValidationError{Name: "protocol.name", Message: "REQUIRED"})
		}
	}
	// In lenient mode: missing protocol.name is allowed when protocol.webdav is present

	if len(validationErrs) > 0 {
		log.Warn("share validation failed", "errors", len(validationErrs))
		WriteValidationError(w, "MISSING_REQUIRED_FIELDS", validationErrs)
		return
	}

	// Step 3: Validate owner and sender OCM address format (F2=A)
	var formatErrs []ValidationError
	if _, _, err := address.Parse(req.Owner); err != nil {
		formatErrs = append(formatErrs, ValidationError{Name: "owner", Message: "INVALID_FORMAT"})
	}
	if _, _, err := address.Parse(req.Sender); err != nil {
		formatErrs = append(formatErrs, ValidationError{Name: "sender", Message: "INVALID_FORMAT"})
	}
	if len(formatErrs) > 0 {
		log.Warn("share owner/sender format invalid", "errors", len(formatErrs))
		WriteValidationError(w, "INVALID_FIELD_FORMAT", formatErrs)
		return
	}

	// Step 4: Enforce protocol support (WebDAV only)
	if req.Protocol.WebDAV == nil {
		log.Warn("share rejected: no webdav protocol")
		WriteProtocolNotSupported(w)
		return
	}

	// Determine effective protocol name
	effectiveProtocolName := req.Protocol.Name
	if effectiveProtocolName == "" && !strictPayloadValidation {
		effectiveProtocolName = "multi"
	}
	if effectiveProtocolName != "webdav" && effectiveProtocolName != "multi" {
		log.Warn("share rejected: unsupported protocol name", "protocol_name", effectiveProtocolName)
		WriteProtocolNotSupported(w)
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
			writeOCMError(w, http.StatusForbidden, msg)
			return
		}
	}

	// Step 5: Parse shareWith using last-@ semantics
	identifier, shareWithProvider, err := address.Parse(req.ShareWith)
	if err != nil {
		log.Warn("invalid shareWith format", "share_with", req.ShareWith, "error", err)
		WriteValidationError(w, "INVALID_SHARE_WITH", []ValidationError{
			{Name: "shareWith", Message: "INVALID_FORMAT"},
		})
		return
	}

	// Step 6: Provider match via hostport normalization
	normalizedProvider, err := hostport.Normalize(shareWithProvider, h.localScheme)
	if err != nil {
		log.Warn("failed to normalize shareWith provider", "provider", shareWithProvider, "error", err)
		WriteValidationError(w, "PROVIDER_MISMATCH", []ValidationError{
			{Name: "shareWith", Message: "PROVIDER_MISMATCH"},
		})
		return
	}

	if !strings.EqualFold(normalizedProvider, h.localProviderFQDNForCompare) {
		log.Warn("provider mismatch",
			"share_with_provider", normalizedProvider,
			"local_provider", h.localProviderFQDNForCompare)
		WriteValidationError(w, "PROVIDER_MISMATCH", []ValidationError{
			{Name: "shareWith", Message: "PROVIDER_MISMATCH"},
		})
		return
	}

	// Step 7: Reject unsupported share types with 501; accept all resourceType values (F7=A)
	if req.ShareType != "user" {
		log.Warn("unsupported share type", "share_type", req.ShareType)
		WriteShareTypeNotSupported(w)
		return
	}

	// Step 8: Resolve recipient identity (triple resolution)
	resolvedUser, err := h.resolveRecipient(r.Context(), identifier)
	if err != nil {
		log.Warn("recipient not found", "identifier", identifier)
		WriteValidationError(w, "RECIPIENT_NOT_FOUND", []ValidationError{
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
		json.NewEncoder(w).Encode(shares.CreateShareResponse{
			RecipientDisplayName: existing.RecipientDisplayName,
		})
		return
	}

	// Step 10: Build and store the inbox record
	share := &shares.IncomingShare{
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
		Status:               shares.ShareStatusPending,
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

		if webdav.HasRequirement(shares.RequirementMustExchangeToken) {
			share.MustExchangeToken = true
		}
	}

	if err := h.repo.Create(r.Context(), share); err != nil {
		log.Error("failed to store share", "error", err)
		writeOCMError(w, http.StatusInternalServerError, "STORAGE_ERROR")
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
	json.NewEncoder(w).Encode(shares.CreateShareResponse{
		RecipientDisplayName: share.RecipientDisplayName,
	})
}

// resolveRecipient tries to find a local user by triple resolution order:
// 1. PartyRepo.Get(identifier) - treat as canonical internal user id
// 2. PartyRepo.GetByUsername(identifier)
// 3. PartyRepo.GetByEmail(identifier) - repo normalizes email internally
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

	return nil, errors.New("recipient not found")
}
