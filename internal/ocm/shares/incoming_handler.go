package shares

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/federation"
)

// IncomingHandler handles incoming OCM share endpoints.
type IncomingHandler struct {
	repo         IncomingShareRepo
	policyEngine *federation.PolicyEngine
	logger       *slog.Logger
	strictMode   bool
}

// NewIncomingHandler creates a new incoming shares handler.
func NewIncomingHandler(repo IncomingShareRepo, policyEngine *federation.PolicyEngine, logger *slog.Logger, strictMode bool) *IncomingHandler {
	return &IncomingHandler{
		repo:         repo,
		policyEngine: policyEngine,
		logger:       logger,
		strictMode:   strictMode,
	}
}

// CreateShare handles POST /ocm/shares.
func (h *IncomingHandler) CreateShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req NewShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("failed to parse share request", "error", err)
		h.sendError(w, http.StatusBadRequest, "invalid_json", "failed to parse request body")
		return
	}

	// Validate request
	errs := ValidateNewShareRequest(&req, h.strictMode)
	if errs.HasErrors() {
		h.logger.Warn("share validation failed", "errors", errs.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errs)
		return
	}

	// Extract sender host for policy check and storage
	senderHost := ExtractSenderHost(req.Sender)
	if senderHost == "" {
		h.sendError(w, http.StatusBadRequest, "invalid_sender", "could not extract host from sender")
		return
	}

	// Check trust policy if policy engine is available
	if h.policyEngine != nil {
		// Get peer identity from context (set by signature middleware)
		peerIdentity := crypto.GetPeerIdentity(r.Context())
		authenticated := peerIdentity != nil && peerIdentity.Authenticated

		decision := h.policyEngine.Evaluate(r.Context(), senderHost, authenticated)
		if !decision.Allowed {
			h.logger.Warn("share rejected by policy",
				"sender", senderHost,
				"reason", decision.Reason,
				"authenticated", authenticated)
			h.sendError(w, http.StatusForbidden, decision.ReasonCode, decision.Reason)
			return
		}
	}

	// Build incoming share record
	share := &IncomingShare{
		ProviderID:        req.ProviderID,
		SenderHost:        senderHost,
		Owner:             req.Owner,
		Sender:            req.Sender,
		ShareWith:         req.ShareWith,
		Name:              req.Name,
		Description:       req.Description,
		ResourceType:      req.ResourceType,
		ShareType:         req.ShareType,
		OwnerDisplayName:  req.OwnerDisplayName,
		SenderDisplayName: req.SenderDisplayName,
		Expiration:        req.Expiration,
		Status:            ShareStatusPending,
	}

	// Handle WebDAV protocol
	if req.Protocol.WebDAV != nil {
		webdav := req.Protocol.WebDAV

		// Determine if URI is absolute or relative
		if IsAbsoluteURI(webdav.URI) {
			share.WebDAVURIAbsolute = webdav.URI
			// Leave WebDAVID empty for absolute URIs
		} else {
			share.WebDAVID = webdav.URI
		}

		share.SharedSecret = webdav.SharedSecret
		share.Permissions = webdav.Permissions

		// Store must-exchange-token requirement
		// This is no longer rejected - we store and enforce it at access time
		if webdav.HasRequirement(RequirementMustExchangeToken) {
			share.MustExchangeToken = true
			h.logger.Info("share requires token exchange",
				"providerId", req.ProviderID,
				"sender", senderHost)
		}
	}

	// Store the share
	if err := h.repo.Create(r.Context(), share); err != nil {
		h.logger.Error("failed to store share", "error", err)
		// Check if it's a duplicate
		if err.Error() != "" {
			h.sendError(w, http.StatusConflict, "duplicate_share", err.Error())
			return
		}
		h.sendError(w, http.StatusInternalServerError, "storage_error", "failed to store share")
		return
	}

	h.logger.Info("share created",
		"shareId", share.ShareID,
		"providerId", share.ProviderID,
		"sender", senderHost,
		"shareWith", share.ShareWith)

	// Return success response
	resp := ShareCreatedResponse{}
	// TODO: Add recipientDisplayName lookup in future

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// sendError sends a JSON error response.
func (h *IncomingHandler) sendError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":       code,
		"description": message,
	})
}

// Handler is an alias for backward compatibility.
// Deprecated: Use IncomingHandler instead.
type Handler = IncomingHandler

// NewHandler creates a new incoming shares handler.
// Deprecated: Use NewIncomingHandler instead.
func NewHandler(repo IncomingShareRepo, policyEngine *federation.PolicyEngine, logger *slog.Logger, strictMode bool) *Handler {
	return NewIncomingHandler(repo, policyEngine, logger, strictMode)
}

// HandleCreate is an alias for backward compatibility.
// Deprecated: Use CreateShare instead.
func (h *IncomingHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	h.CreateShare(w, r)
}
