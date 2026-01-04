package shares

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// NotificationSender is an interface for sending notifications to remote servers.
type NotificationSender interface {
	SendShareAccepted(ctx context.Context, targetHost, providerID, resourceType string) error
	SendShareDeclined(ctx context.Context, targetHost, providerID, resourceType string) error
}

// InboxActionsHandler handles accept/decline actions on inbox shares.
type InboxActionsHandler struct {
	repo               IncomingShareRepo
	notificationSender NotificationSender
	logger             *slog.Logger
}

// NewInboxActionsHandler creates a new inbox actions handler.
func NewInboxActionsHandler(repo IncomingShareRepo, sender NotificationSender, logger *slog.Logger) *InboxActionsHandler {
	return &InboxActionsHandler{
		repo:               repo,
		notificationSender: sender,
		logger:             logger,
	}
}

// HandleAccept handles POST /api/inbox/shares/{shareId}/accept.
func (h *InboxActionsHandler) HandleAccept(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	shareID := extractShareID(r.URL.Path, "/accept")
	if shareID == "" {
		h.sendError(w, http.StatusBadRequest, "missing_share_id", "shareId is required")
		return
	}

	ctx := r.Context()

	// Get the share
	share, err := h.repo.GetByID(ctx, shareID)
	if err != nil {
		h.sendError(w, http.StatusNotFound, "share_not_found", "share not found")
		return
	}

	// Check current status
	if share.Status == ShareStatusAccepted {
		// Already accepted, idempotent success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  string(ShareStatusAccepted),
			"shareId": shareID,
		})
		return
	}

	if share.Status == ShareStatusDeclined {
		h.sendError(w, http.StatusConflict, "already_declined", "share has already been declined")
		return
	}

	// Update status
	if err := h.repo.UpdateStatus(ctx, shareID, ShareStatusAccepted); err != nil {
		h.logger.Error("failed to update share status", "shareId", shareID, "error", err)
		h.sendError(w, http.StatusInternalServerError, "update_failed", "failed to update share status")
		return
	}

	// Send notification to sender
	if h.notificationSender != nil {
		if err := h.notificationSender.SendShareAccepted(ctx, share.SenderHost, share.ProviderID, share.ResourceType); err != nil {
			// Log but don't fail - the share is already accepted locally
			h.logger.Warn("failed to send accept notification",
				"shareId", shareID,
				"senderHost", share.SenderHost,
				"error", err)
		} else {
			h.logger.Info("share accepted notification sent",
				"shareId", shareID,
				"providerId", share.ProviderID,
				"senderHost", share.SenderHost)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  string(ShareStatusAccepted),
		"shareId": shareID,
	})
}

// HandleDecline handles POST /api/inbox/shares/{shareId}/decline.
func (h *InboxActionsHandler) HandleDecline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	shareID := extractShareID(r.URL.Path, "/decline")
	if shareID == "" {
		h.sendError(w, http.StatusBadRequest, "missing_share_id", "shareId is required")
		return
	}

	ctx := r.Context()

	// Get the share
	share, err := h.repo.GetByID(ctx, shareID)
	if err != nil {
		h.sendError(w, http.StatusNotFound, "share_not_found", "share not found")
		return
	}

	// Check current status
	if share.Status == ShareStatusDeclined {
		// Already declined, idempotent success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  string(ShareStatusDeclined),
			"shareId": shareID,
		})
		return
	}

	if share.Status == ShareStatusAccepted {
		h.sendError(w, http.StatusConflict, "already_accepted", "share has already been accepted")
		return
	}

	// Update status
	if err := h.repo.UpdateStatus(ctx, shareID, ShareStatusDeclined); err != nil {
		h.logger.Error("failed to update share status", "shareId", shareID, "error", err)
		h.sendError(w, http.StatusInternalServerError, "update_failed", "failed to update share status")
		return
	}

	// Send notification to sender
	if h.notificationSender != nil {
		if err := h.notificationSender.SendShareDeclined(ctx, share.SenderHost, share.ProviderID, share.ResourceType); err != nil {
			// Log but don't fail - the share is already declined locally
			h.logger.Warn("failed to send decline notification",
				"shareId", shareID,
				"senderHost", share.SenderHost,
				"error", err)
		} else {
			h.logger.Info("share declined notification sent",
				"shareId", shareID,
				"providerId", share.ProviderID,
				"senderHost", share.SenderHost)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  string(ShareStatusDeclined),
		"shareId": shareID,
	})
}

// extractShareID extracts the shareId from the request path.
// Expected path format: /api/inbox/shares/{shareId}/accept or /api/inbox/shares/{shareId}/decline
func extractShareID(path, suffix string) string {
	// Remove the suffix (/accept or /decline)
	path = strings.TrimSuffix(path, suffix)

	// Find the last path segment
	parts := strings.Split(path, "/")
	if len(parts) < 1 {
		return ""
	}

	return parts[len(parts)-1]
}

// sendError sends a JSON error response.
func (h *InboxActionsHandler) sendError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":       code,
		"description": message,
	})
}
