package shares

import (
	"encoding/json"
	"net/http"
)

// InboxHandler handles inbox-related endpoints.
// Temporary: will be replaced by internal/components/api/inbox/shares in p07.
type InboxHandler struct {
	repo IncomingShareRepo
}

// NewInboxHandler creates a new inbox handler.
func NewInboxHandler(repo IncomingShareRepo) *InboxHandler {
	return &InboxHandler{repo: repo}
}

// InboxListResponse is the response for GET /api/inbox/shares.
type InboxListResponse struct {
	Shares []InboxShareView `json:"shares"`
}

// HandleList handles GET /api/inbox/shares.
// Temporary: passes empty recipientUserID. p07 will inject CurrentUser.
func (h *InboxHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// Temporary: no user scoping until CurrentUser injection in p07.
	// Empty recipientUserID returns no shares (correct for compilation).
	shares, err := h.repo.ListByRecipientUserID(ctx, "")
	if err != nil {
		http.Error(w, "failed to list shares", http.StatusInternalServerError)
		return
	}

	views := make([]InboxShareView, 0, len(shares))
	for _, s := range shares {
		views = append(views, s.ToView())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(InboxListResponse{Shares: views})
}
