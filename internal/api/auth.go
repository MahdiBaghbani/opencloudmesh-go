package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
)

// SessionTTL is the default session duration.
const SessionTTL = 24 * time.Hour

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	repo     identity.PartyRepo
	sessions identity.SessionRepo
	auth     *identity.UserAuth
}

// NewAuthHandler creates a new authentication handler.
func NewAuthHandler(repo identity.PartyRepo, sessions identity.SessionRepo, auth *identity.UserAuth) *AuthHandler {
	return &AuthHandler{
		repo:     repo,
		sessions: sessions,
		auth:     auth,
	}
}

// LoginRequest is the request body for login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is the response for a successful login.
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	User      struct {
		ID          string `json:"id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
	} `json:"user"`
}

// Login handles POST /api/auth/login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}

	if req.Username == "" || req.Password == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "username and password required")
		return
	}

	ctx := r.Context()

	// Authenticate user
	user, err := h.auth.Authenticate(ctx, h.repo, req.Username, req.Password)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}

	// Create session
	session, err := h.sessions.Create(ctx, user.ID, SessionTTL)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "session_error", "failed to create session")
		return
	}

	// Set cookie for browser clients
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.Token,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	resp := LoginResponse{
		Token:     session.Token,
		ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
	}
	resp.User.ID = user.ID
	resp.User.Username = user.Username
	resp.User.DisplayName = user.DisplayName
	resp.User.Role = user.Role

	writeJSON(w, http.StatusOK, resp)
}

// Logout handles POST /api/auth/logout.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := extractToken(r)
	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "no_session", "no session token provided")
		return
	}

	ctx := r.Context()
	h.sessions.Delete(ctx, token)

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// GetCurrentUser handles GET /api/auth/me.
func (h *AuthHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "no_session", "no session token provided")
		return
	}

	ctx := r.Context()
	session, err := h.sessions.Get(ctx, token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid_session", "session expired or invalid")
		return
	}

	user, err := h.repo.Get(ctx, session.UserID)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "user_not_found", "user not found")
		return
	}

	resp := struct {
		ID          string `json:"id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email,omitempty"`
		Role        string `json:"role"`
	}{
		ID:          user.ID,
		Username:    user.Username,
		DisplayName: user.DisplayName,
		Email:       user.Email,
		Role:        user.Role,
	}

	writeJSON(w, http.StatusOK, resp)
}

// extractToken gets the session token from Authorization header or cookie.
func extractToken(r *http.Request) string {
	// Try Authorization header first
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}

	// Fall back to cookie
	cookie, err := r.Cookie("session")
	if err == nil {
		return cookie.Value
	}

	return ""
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}
