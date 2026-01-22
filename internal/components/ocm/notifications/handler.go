package notifications

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
)

// Handler handles OCM notification endpoints.
type Handler struct {
	outgoingRepo shares.OutgoingShareRepo
	logger       *slog.Logger
}

// NewHandler creates a new notifications handler.
func NewHandler(outgoingRepo shares.OutgoingShareRepo, logger *slog.Logger) *Handler {
	return &Handler{
		outgoingRepo: outgoingRepo,
		logger:       logger,
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
	var req NewNotification
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
	if !IsValidNotificationType(req.NotificationType) {
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
	var senderHost string
	peerIdentity := crypto.GetPeerIdentity(r.Context())
	if peerIdentity != nil && peerIdentity.Authenticated {
		senderHost = peerIdentity.Host
	}

	// Look up the outgoing share by providerId
	share, err := h.outgoingRepo.GetByProviderID(r.Context(), req.ProviderID)
	if err != nil {
		// If no signature verified, we can't verify the sender
		if senderHost == "" {
			// Check if there's exactly one share with this providerId
			// Since our repo is keyed by providerId globally, we either find it or not
			log.Warn("notification for unknown share", "provider_id", req.ProviderID)
			h.sendError(w, http.StatusNotFound, "share_not_found", "no share found for providerId")
			return
		}
		log.Warn("notification for unknown share", "provider_id", req.ProviderID, "sender", senderHost)
		h.sendError(w, http.StatusNotFound, "share_not_found", "no share found for providerId")
		return
	}

	// If we have a verified sender, validate it matches the share's receiver
	if senderHost != "" && share.ReceiverHost != senderHost {
		log.Warn("notification sender mismatch",
			"provider_id", req.ProviderID,
			"expected", share.ReceiverHost,
			"got", senderHost)
		h.sendError(w, http.StatusForbidden, "sender_mismatch", "notification sender does not match share receiver")
		return
	}

	// Process the notification
	switch req.NotificationType {
	case NotificationShareAccepted:
		log.Info("share accepted notification",
			"provider_id", req.ProviderID,
			"share_id", share.ShareID,
			"receiver", share.ReceiverHost)
		// Update share status (in a real implementation, would update persistence)
		// For now, just log the acceptance

	case NotificationShareDeclined:
		log.Info("share declined notification",
			"provider_id", req.ProviderID,
			"share_id", share.ShareID,
			"receiver", share.ReceiverHost)
		// Update share status

	case NotificationShareUnshared:
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
