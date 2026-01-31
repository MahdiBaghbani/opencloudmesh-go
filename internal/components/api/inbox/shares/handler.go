// Package shares implements session-gated inbox share handlers.
// All endpoints enforce per-user scoping via the injected CurrentUser resolver.
package shares

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// InboxListResponse wraps the share views returned by HandleList.
type InboxListResponse struct {
	Shares []shares.InboxShareView `json:"shares"`
}

// Handler handles inbox share list, accept, and decline endpoints.
type Handler struct {
	repo        shares.IncomingShareRepo
	sender      shares.NotificationSender
	currentUser func(context.Context) (*identity.User, error)
	log         *slog.Logger
}

// NewHandler creates a new inbox shares handler.
func NewHandler(
	repo shares.IncomingShareRepo,
	sender shares.NotificationSender,
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

	views := make([]shares.InboxShareView, 0, len(result))
	for _, s := range result {
		views = append(views, s.ToView())
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
		if errors.Is(err, shares.ErrShareNotFound) {
			api.WriteNotFound(w, "share not found")
			return
		}
		h.log.Error("failed to get share", "share_id", shareID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get share")
		return
	}

	if share.Status == shares.ShareStatusAccepted {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  string(shares.ShareStatusAccepted),
			"shareId": shareID,
		})
		return
	}

	if share.Status == shares.ShareStatusDeclined {
		api.WriteConflict(w, "share has already been declined")
		return
	}

	if err := h.repo.UpdateStatusForRecipientUserID(ctx, shareID, user.ID, shares.ShareStatusAccepted); err != nil {
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
		"status":  string(shares.ShareStatusAccepted),
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
		if errors.Is(err, shares.ErrShareNotFound) {
			api.WriteNotFound(w, "share not found")
			return
		}
		h.log.Error("failed to get share", "share_id", shareID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get share")
		return
	}

	if share.Status == shares.ShareStatusDeclined {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  string(shares.ShareStatusDeclined),
			"shareId": shareID,
		})
		return
	}

	if share.Status == shares.ShareStatusAccepted {
		api.WriteConflict(w, "share has already been accepted")
		return
	}

	if err := h.repo.UpdateStatusForRecipientUserID(ctx, shareID, user.ID, shares.ShareStatusDeclined); err != nil {
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
		"status":  string(shares.ShareStatusDeclined),
		"shareId": shareID,
	})
}
