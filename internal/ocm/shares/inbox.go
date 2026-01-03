package shares

import (
	"encoding/json"
	"net/http"
)

// InboxHandler handles inbox-related endpoints.
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
func (h *InboxHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get user from context (set by auth middleware)
	// For now, list all shares (auth middleware not yet integrated)
	// TODO: Extract authenticated user and filter by shareWith

	ctx := r.Context()

	// Get shareWith filter from query param if provided
	shareWith := r.URL.Query().Get("shareWith")

	var shares []*IncomingShare
	var err error

	if shareWith != "" {
		shares, err = h.repo.ListByUser(ctx, shareWith)
	} else {
		// List all (for now, until auth is wired)
		shares, err = h.repo.ListByUser(ctx, "")
	}

	if err != nil {
		http.Error(w, "failed to list shares", http.StatusInternalServerError)
		return
	}

	// Convert to safe view (excludes secrets)
	views := make([]InboxShareView, 0, len(shares))
	for _, s := range shares {
		views = append(views, s.ToView())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(InboxListResponse{Shares: views})
}
