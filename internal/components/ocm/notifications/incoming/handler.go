package incoming

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// Handler handles OCM notification endpoints.
type Handler struct {
	outgoingRepo sharesoutgoing.OutgoingShareRepo
	logger       *slog.Logger
	localScheme  string // scheme from PublicOrigin for comparison normalization
}

// NewHandler creates a new notifications handler.
// publicOrigin is the local instance's PublicOrigin (validated at config load).
func NewHandler(outgoingRepo sharesoutgoing.OutgoingShareRepo, publicOrigin string, logger *slog.Logger) *Handler {
	var localScheme string
	if u, err := url.Parse(publicOrigin); err == nil && u.Scheme != "" {
		localScheme = u.Scheme
	}

	return &Handler{
		outgoingRepo: outgoingRepo,
		logger:       logger,
		localScheme:  localScheme,
	}
}

// HandleNotification handles POST /ocm/notifications.
func (h *Handler) HandleNotification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get request-scoped logger with request correlation fields
	log := appctx.GetLogger(r.Context())

	// Parse request body
	var req notifications.NewNotification
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("failed to parse notification request", "error", err)
		h.sendError(w, http.StatusBadRequest, "invalid_json", "failed to parse request body")
		return
	}

	// Validate required fields
	if req.NotificationType == "" {
		h.sendError(w, http.StatusBadRequest, "missing_field", "notificationType is required")
		return
	}
	if !notifications.IsValidNotificationType(req.NotificationType) {
		h.sendError(w, http.StatusBadRequest, "invalid_notification_type", "unsupported notification type")
		return
	}
	if req.ResourceType == "" {
		h.sendError(w, http.StatusBadRequest, "missing_field", "resourceType is required")
		return
	}
	if req.ProviderID == "" {
		h.sendError(w, http.StatusBadRequest, "missing_field", "providerId is required")
		return
	}

	// Get sender identity from signature (if available)
	var senderAuthority string
	peerIdentity := crypto.GetPeerIdentity(r.Context())
	if peerIdentity != nil && peerIdentity.Authenticated {
		senderAuthority = peerIdentity.AuthorityForCompare
	}

	// Look up the outgoing share by providerId
	share, err := h.outgoingRepo.GetByProviderID(r.Context(), req.ProviderID)
	if err != nil {
		// If no signature verified, we can't verify the sender
		if senderAuthority == "" {
			// Check if there's exactly one share with this providerId
			// Since our repo is keyed by providerId globally, we either find it or not
			log.Warn("notification for unknown share", "provider_id", req.ProviderID)
			h.sendError(w, http.StatusNotFound, "share_not_found", "no share found for providerId")
			return
		}
		log.Warn("notification for unknown share", "provider_id", req.ProviderID, "sender", senderAuthority)
		h.sendError(w, http.StatusNotFound, "share_not_found", "no share found for providerId")
		return
	}

	// If we have a verified sender, validate it matches the share's receiver
	if senderAuthority != "" {
		normalizedReceiver, err := hostport.Normalize(share.ReceiverHost, h.localScheme)
		if err != nil {
			log.Warn("failed to normalize share receiver host",
				"host", share.ReceiverHost, "error", err)
			// Skip mismatch enforcement on normalization error (no new rejection path)
		} else if normalizedReceiver != senderAuthority {
			log.Warn("notification sender mismatch",
				"provider_id", req.ProviderID,
				"expected", normalizedReceiver,
				"got", senderAuthority)
			h.sendError(w, http.StatusForbidden, "sender_mismatch", "notification sender does not match share receiver")
			return
		}
	}

	// Process the notification
	switch req.NotificationType {
	case notifications.NotificationShareAccepted:
		log.Info("share accepted notification",
			"provider_id", req.ProviderID,
			"share_id", share.ShareID,
			"receiver", share.ReceiverHost)

	case notifications.NotificationShareDeclined:
		log.Info("share declined notification",
			"provider_id", req.ProviderID,
			"share_id", share.ShareID,
			"receiver", share.ReceiverHost)

	case notifications.NotificationShareUnshared:
		log.Info("share unshared notification",
			"provider_id", req.ProviderID,
			"share_id", share.ShareID,
			"receiver", share.ReceiverHost)
	}

	// Return success (empty response per spec)
	w.WriteHeader(http.StatusCreated)
}

// sendError sends a JSON error response.
func (h *Handler) sendError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":       code,
		"description": message,
	})
}
