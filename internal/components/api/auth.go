// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
)

const (
	SessionTTL = 24 * time.Hour //nolint:revive // exported: obvious default auth session TTL duration constant

	maxLoginBodyBytes = 4096
)

// AuthHandler serves login, logout, and current-user endpoints.
type AuthHandler struct {
	repo     identity.PartyRepo
	sessions identity.SessionRepo
	auth     *identity.UserAuth
}

// NewAuthHandler returns an AuthHandler with the given identity components.
func NewAuthHandler(repo identity.PartyRepo, sessions identity.SessionRepo, auth *identity.UserAuth) *AuthHandler {
	return &AuthHandler{
		repo:     repo,
		sessions: sessions,
		auth:     auth,
	}
}

// LoginRequest carries the body for POST /api/auth/login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse carries the body returned by POST /api/auth/login.
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
	User      struct {
		ID          string `json:"id"`
		Username    string `json:"username"`
		DisplayName string `json:"displayName"`
		Role        string `json:"role"`
	} `json:"user"`
}

// Login handles POST /api/auth/login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")

			return
		}

		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")

		return
	}

	var req LoginRequest
	if unmarshalErr := json.Unmarshal(body, &req); unmarshalErr != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")

		return
	}

	if req.Username == "" || req.Password == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "username and password required")

		return
	}

	ctx := r.Context()

	user, err := h.auth.Authenticate(ctx, h.repo, req.Username, req.Password)
	if err != nil {
		if identity.IsInfrastructureError(err) {
			appctx.GetLogger(ctx).Warn("login authentication failed", "error", err)
			WriteInternalError(w, "internal server error")

			return
		}

		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")

		return
	}

	session, err := h.sessions.Create(ctx, user.ID, SessionTTL)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "session_error", "failed to create session")

		return
	}

	// Set cookie for browser clients
	//nolint:gosec // cookie sets HttpOnly, SameSite:Lax, and Secure from validated HTTPS transport state
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.Token,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   realip.RequestUsesHTTPS(r),
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

// Logout handles POST /api/auth/logout and clears the session cookie.
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
	if err := h.sessions.Delete(ctx, token); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "session_error", "failed to delete session")

		return
	}

	//nolint:gosec // deletion cookie mirrors the login cookie flags (HttpOnly, SameSite:Lax, Secure from validated HTTPS transport state)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   realip.RequestUsesHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// GetCurrentUser handles GET /api/auth/me and returns the authenticated user.
func (h *AuthHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "no_session", "no session token provided")

		return
	}

	ctx := r.Context()

	session, err := h.sessions.Get(ctx, token)
	if err != nil {
		if identity.IsInfrastructureError(err) {
			appctx.GetLogger(ctx).Warn("session lookup failed", "error", err)
			WriteInternalError(w, "internal server error")

			return
		}

		writeJSONError(w, http.StatusUnauthorized, "invalid_session", "session expired or invalid")

		return
	}

	user, err := h.repo.Get(ctx, session.UserID)
	if err != nil {
		if identity.IsInfrastructureError(err) {
			appctx.GetLogger(ctx).Warn("user lookup failed", "error", err)
			WriteInternalError(w, "internal server error")

			return
		}

		writeJSONError(w, http.StatusUnauthorized, "user_not_found", "user not found")

		return
	}

	resp := struct {
		ID          string `json:"id"`
		Username    string `json:"username"`
		DisplayName string `json:"displayName"`
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

// extractToken returns the session token from Authorization header or session cookie.
func extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}

	cookie, err := r.Cookie("session")
	if err == nil {
		return cookie.Value
	}

	return ""
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:errcheck,errchkjson // response already committed after WriteHeader; write error cannot be recovered or meaningfully handled; payload encodes to fixed JSON, so encode error is always nil
	json.NewEncoder(w).Encode(data)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:errcheck,errchkjson // response already committed after WriteHeader; write error cannot be recovered or meaningfully handled; payload encodes to fixed JSON, so encode error is always nil
	json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}
