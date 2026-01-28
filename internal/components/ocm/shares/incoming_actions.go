package shares

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
)

// NotificationSender is an interface for sending notifications to remote servers.
type NotificationSender interface {
	SendShareAccepted(ctx context.Context, targetHost, providerID, resourceType string) error
	SendShareDeclined(ctx context.Context, targetHost, providerID, resourceType string) error
}

// InboxActionsHandler handles accept/decline actions on inbox shares.
// Temporary: will be replaced by internal/components/api/inbox/shares in p07.
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
// Temporary: passes empty recipientUserID. p07 will inject CurrentUser.
func (h *InboxActionsHandler) HandleAccept(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log := appctx.GetLogger(r.Context())

	shareID := extractShareID(r.URL.Path, "/accept")
	if shareID == "" {
		h.sendError(w, http.StatusBadRequest, "missing_share_id", "shareId is required")
		return
	}

	ctx := r.Context()

	// Temporary: empty recipientUserID until p07 CurrentUser injection
	share, err := h.repo.GetByIDForRecipientUserID(ctx, shareID, "")
	if err != nil {
		h.sendError(w, http.StatusNotFound, "share_not_found", "share not found")
		return
	}

	if share.Status == ShareStatusAccepted {
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

	if err := h.repo.UpdateStatusForRecipientUserID(ctx, shareID, "", ShareStatusAccepted); err != nil {
		log.Error("failed to update share status", "share_id", shareID, "error", err)
		h.sendError(w, http.StatusInternalServerError, "update_failed", "failed to update share status")
		return
	}

	if h.notificationSender != nil {
		if err := h.notificationSender.SendShareAccepted(ctx, share.SenderHost, share.ProviderID, share.ResourceType); err != nil {
			log.Warn("failed to send accept notification",
				"share_id", shareID,
				"sender_host", share.SenderHost,
				"error", err)
		} else {
			log.Info("share accepted notification sent",
				"share_id", shareID,
				"provider_id", share.ProviderID,
				"sender_host", share.SenderHost)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  string(ShareStatusAccepted),
		"shareId": shareID,
	})
}

// HandleDecline handles POST /api/inbox/shares/{shareId}/decline.
// Temporary: passes empty recipientUserID. p07 will inject CurrentUser.
func (h *InboxActionsHandler) HandleDecline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log := appctx.GetLogger(r.Context())

	shareID := extractShareID(r.URL.Path, "/decline")
	if shareID == "" {
		h.sendError(w, http.StatusBadRequest, "missing_share_id", "shareId is required")
		return
	}

	ctx := r.Context()

	share, err := h.repo.GetByIDForRecipientUserID(ctx, shareID, "")
	if err != nil {
		h.sendError(w, http.StatusNotFound, "share_not_found", "share not found")
		return
	}

	if share.Status == ShareStatusDeclined {
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

	if err := h.repo.UpdateStatusForRecipientUserID(ctx, shareID, "", ShareStatusDeclined); err != nil {
		log.Error("failed to update share status", "share_id", shareID, "error", err)
		h.sendError(w, http.StatusInternalServerError, "update_failed", "failed to update share status")
		return
	}

	if h.notificationSender != nil {
		if err := h.notificationSender.SendShareDeclined(ctx, share.SenderHost, share.ProviderID, share.ResourceType); err != nil {
			log.Warn("failed to send decline notification",
				"share_id", shareID,
				"sender_host", share.SenderHost,
				"error", err)
		} else {
			log.Info("share declined notification sent",
				"share_id", shareID,
				"provider_id", share.ProviderID,
				"sender_host", share.SenderHost)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  string(ShareStatusDeclined),
		"shareId": shareID,
	})
}

func extractShareID(path, suffix string) string {
	path = strings.TrimSuffix(path, suffix)
	parts := strings.Split(path, "/")
	if len(parts) < 1 {
		return ""
	}
	return parts[len(parts)-1]
}

func (h *InboxActionsHandler) sendError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":       code,
		"description": message,
	})
}
