// Package shares implements session-gated inbox share handlers.
// All endpoints enforce per-user scoping via the injected CurrentUser resolver.
package shares

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// InboxShareView is the safe view of an IncomingShare for API responses.
// It explicitly excludes sensitive fields like SharedSecret.
type InboxShareView struct {
	ShareID           string                `json:"shareId"`
	ProviderID        string                `json:"providerId"`
	Name              string                `json:"name"`
	Description       string                `json:"description,omitempty"`
	Owner             string                `json:"owner"`
	Sender            string                `json:"sender"`
	SenderHost        string                `json:"senderHost"`
	ShareWith         string                `json:"shareWith"`
	ResourceType      string                `json:"resourceType"`
	ShareType         string                `json:"shareType"`
	Permissions       []string              `json:"permissions"`
	Status            sharesinbox.ShareStatus `json:"status"`
	CreatedAt         time.Time             `json:"createdAt"`
	OwnerDisplayName  string                `json:"ownerDisplayName,omitempty"`
	SenderDisplayName string                `json:"senderDisplayName,omitempty"`
}

// NewInboxShareView converts an IncomingShare to a safe view for API responses.
func NewInboxShareView(s *sharesinbox.IncomingShare) InboxShareView {
	return InboxShareView{
		ShareID:           s.ShareID,
		ProviderID:        s.ProviderID,
		Name:              s.Name,
		Description:       s.Description,
		Owner:             s.Owner,
		Sender:            s.Sender,
		SenderHost:        s.SenderHost,
		ShareWith:         s.ShareWith,
		ResourceType:      s.ResourceType,
		ShareType:         s.ShareType,
		Permissions:       s.Permissions,
		Status:            s.Status,
		CreatedAt:         s.CreatedAt,
		OwnerDisplayName:  s.OwnerDisplayName,
		SenderDisplayName: s.SenderDisplayName,
	}
}

// InboxListResponse wraps the share views returned by HandleList.
type InboxListResponse struct {
	Shares []InboxShareView `json:"shares"`
}

// Handler handles inbox share list, accept, and decline endpoints.
type Handler struct {
	repo        sharesinbox.IncomingShareRepo
	sender      sharesinbox.NotificationSender
	currentUser func(context.Context) (*identity.User, error)
	log         *slog.Logger
}

// NewHandler creates a new inbox shares handler.
func NewHandler(
	repo sharesinbox.IncomingShareRepo,
	sender sharesinbox.NotificationSender,
	currentUser func(context.Context) (*identity.User, error),
	log *slog.Logger,
) *Handler {
	log = logutil.NoopIfNil(log)
	return &Handler{
		repo:        repo,
		sender:      sender,
		currentUser: currentUser,
		log:         log,
	}
}

// HandleList handles GET /api/inbox/shares.
// Lists only shares owned by the authenticated user.
func (h *Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	result, err := h.repo.ListByRecipientUserID(r.Context(), user.ID)
	if err != nil {
		h.log.Error("failed to list inbox shares", "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to list inbox shares")
		return
	}

	views := make([]InboxShareView, 0, len(result))
	for _, s := range result {
		views = append(views, NewInboxShareView(s))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(InboxListResponse{Shares: views})
}

// HandleAccept handles POST /api/inbox/shares/{shareId}/accept.
// Enforces ownership by construction: the repo returns not-found for cross-user access.
func (h *Handler) HandleAccept(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	shareID := chi.URLParam(r, "shareId")
	if shareID == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "shareId is required")
		return
	}

	ctx := r.Context()

	share, err := h.repo.GetByIDForRecipientUserID(ctx, shareID, user.ID)
	if err != nil {
		if errors.Is(err, sharesinbox.ErrShareNotFound) {
			api.WriteNotFound(w, "share not found")
			return
		}
		h.log.Error("failed to get share", "share_id", shareID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get share")
		return
	}

	if share.Status == sharesinbox.ShareStatusAccepted {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  string(sharesinbox.ShareStatusAccepted),
			"shareId": shareID,
		})
		return
	}

	if share.Status == sharesinbox.ShareStatusDeclined {
		api.WriteConflict(w, "share has already been declined")
		return
	}

	if err := h.repo.UpdateStatusForRecipientUserID(ctx, shareID, user.ID, sharesinbox.ShareStatusAccepted); err != nil {
		h.log.Error("failed to update share status", "share_id", shareID, "error", err)
		api.WriteInternalError(w, "failed to update share status")
		return
	}

	if h.sender != nil {
		if err := h.sender.SendShareAccepted(ctx, share.SenderHost, share.ProviderID, share.ResourceType); err != nil {
			h.log.Warn("failed to send accept notification",
				"share_id", shareID,
				"sender_host", share.SenderHost,
				"error", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  string(sharesinbox.ShareStatusAccepted),
		"shareId": shareID,
	})
}

// HandleDecline handles POST /api/inbox/shares/{shareId}/decline.
// Enforces ownership by construction: the repo returns not-found for cross-user access.
func (h *Handler) HandleDecline(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	shareID := chi.URLParam(r, "shareId")
	if shareID == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "shareId is required")
		return
	}

	ctx := r.Context()

	share, err := h.repo.GetByIDForRecipientUserID(ctx, shareID, user.ID)
	if err != nil {
		if errors.Is(err, sharesinbox.ErrShareNotFound) {
			api.WriteNotFound(w, "share not found")
			return
		}
		h.log.Error("failed to get share", "share_id", shareID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get share")
		return
	}

	if share.Status == sharesinbox.ShareStatusDeclined {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  string(sharesinbox.ShareStatusDeclined),
			"shareId": shareID,
		})
		return
	}

	if share.Status == sharesinbox.ShareStatusAccepted {
		api.WriteConflict(w, "share has already been accepted")
		return
	}

	if err := h.repo.UpdateStatusForRecipientUserID(ctx, shareID, user.ID, sharesinbox.ShareStatusDeclined); err != nil {
		h.log.Error("failed to update share status", "share_id", shareID, "error", err)
		api.WriteInternalError(w, "failed to update share status")
		return
	}

	if h.sender != nil {
		if err := h.sender.SendShareDeclined(ctx, share.SenderHost, share.ProviderID, share.ResourceType); err != nil {
			h.log.Warn("failed to send decline notification",
				"share_id", shareID,
				"sender_host", share.SenderHost,
				"error", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  string(sharesinbox.ShareStatusDeclined),
		"shareId": shareID,
	})
}
