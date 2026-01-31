// Package auth provides session authentication middleware for HTTP servers.
package auth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

type contextKey string

const (
	sessionContextKey contextKey = "session"
	userContextKey    contextKey = "user"
)

// AuthGateConfig configures the session auth gate middleware.
type AuthGateConfig struct {
	// RequireAuth returns true if the given path requires session authentication.
	// Constructed by the server at router setup time using IsAuthRequired().
	RequireAuth func(path string) bool

	// Log is the base logger for auth-related warnings and errors.
	Log *slog.Logger

	// SessionRepo provides session lookup by token.
	// May be nil only if RequireAuth always returns false (tests only).
	SessionRepo identity.SessionRepo

	// PartyRepo provides user lookup by ID.
	// May be nil only if RequireAuth always returns false (tests only).
	PartyRepo identity.PartyRepo
}

// NewAuthGate returns a middleware that enforces session authentication.
// If RequireAuth returns false for the request path, the request passes through
// without token parsing, session validation, or context enrichment.
func NewAuthGate(cfg AuthGateConfig) func(http.Handler) http.Handler {
	cfg.Log = logutil.NoopIfNil(cfg.Log)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.RequireAuth(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Extract session token from cookie or Authorization header
			sessionToken := extractSessionToken(r)
			if sessionToken == "" {
				api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
				return
			}

			// Validate session
			session, err := cfg.SessionRepo.Get(r.Context(), sessionToken)
			if err != nil {
				api.WriteUnauthorized(w, api.ReasonUnauthenticated, "session not found or expired")
				return
			}

			// Check session expiry
			if session.IsExpired() {
				api.WriteUnauthorized(w, api.ReasonSessionExpired, "session has expired")
				return
			}

			// Get associated user
			user, err := cfg.PartyRepo.Get(r.Context(), session.UserID)
			if err != nil {
				api.WriteUnauthorized(w, api.ReasonUnauthenticated, "session user not found")
				return
			}

			// Add session and user to context
			ctx := r.Context()
			ctx = context.WithValue(ctx, sessionContextKey, session)
			ctx = context.WithValue(ctx, userContextKey, user)

			// Enrich handler logger with user_id (not used by access log, handler-only)
			reqLogger := appctx.GetLogger(ctx).With("user_id", session.UserID)
			ctx = appctx.WithLogger(ctx, reqLogger)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractSessionToken gets the session token from cookie or Authorization header.
func extractSessionToken(r *http.Request) string {
	// Try cookie first
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// Try Authorization header (Bearer token)
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	return ""
}

// GetSessionFromContext returns the session from request context.
func GetSessionFromContext(ctx context.Context) *identity.Session {
	session, _ := ctx.Value(sessionContextKey).(*identity.Session)
	return session
}

// GetUserFromContext returns the user from request context.
func GetUserFromContext(ctx context.Context) *identity.User {
	user, _ := ctx.Value(userContextKey).(*identity.User)
	return user
}
