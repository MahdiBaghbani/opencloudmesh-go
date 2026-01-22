package server

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
)

type contextKey string

const (
	// SessionContextKey is the context key for the current session.
	SessionContextKey contextKey = "session"
	// UserContextKey is the context key for the current user.
	UserContextKey contextKey = "user"
)

// loggingMiddleware logs request information using slog.
// It uses the request-scoped logger from context (set by RequestLoggerMiddleware)
// which already has request_id, method, path, client_ip attached.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		defer func() {
			// Get logger from context (has request_id, method, path, client_ip)
			logger, ok := appctx.LoggerFromContext(r.Context())

			// Fallback: if context logger missing, recompute base fields
			if !ok {
				reqID := middleware.GetReqID(r.Context())
				clientIP := "unknown"
				if d := deps.GetDeps(); d != nil && d.RealIP != nil {
					clientIP = d.RealIP.GetClientIPString(r)
				}
				logger = s.logger.With(
					"request_id", reqID,
					"method", r.Method,
					"path", r.URL.Path,
					"client_ip", clientIP,
				)
			}

			// Add response fields (access log contract). Do not attempt to include:
			// - user_id (auth middleware runs after logging middleware)
			// - peer fields (signature middleware runs inside /ocm route groups)
			//
			// IMPORTANT: The context logger already has request_id, method, path,
			// client_ip attached by RequestLoggerMiddleware. We only add response
			// fields here. Do NOT re-add base fields or you will get duplicate keys.
			logger.Info("request",
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
			)
		}()

		next.ServeHTTP(ww, r)
	})
}

// authMiddleware enforces session authentication.
// Public endpoints (discovery, health, login) bypass auth.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this path requires authentication
		if !IsAuthRequired(r.URL.Path, s.cfg.ExternalBasePath, s.mountedServices) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract session token from cookie or header
		sessionToken := extractSessionToken(r)
		if sessionToken == "" {
			api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
			return
		}

		// Get deps from SharedDeps
		d := deps.GetDeps()

		// Validate session
		session, err := d.SessionRepo.Get(r.Context(), sessionToken)
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
		user, err := d.PartyRepo.Get(r.Context(), session.UserID)
		if err != nil {
			api.WriteUnauthorized(w, api.ReasonUnauthenticated, "session user not found")
			return
		}

		// Add session and user to context
		ctx := r.Context()
		ctx = context.WithValue(ctx, SessionContextKey, session)
		ctx = context.WithValue(ctx, UserContextKey, user)

		// Enrich handler logger with user_id (not used by access log, handler-only)
		reqLogger := appctx.GetLogger(ctx).With("user_id", session.UserID)
		ctx = appctx.WithLogger(ctx, reqLogger)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
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


// RateLimitConfig holds configuration for a rate-limited endpoint.
type RateLimitConfig struct {
	RequestsPerMinute int
	Burst             int
}

// simpleRateLimiter is an in-memory rate limiter per key.
type simpleRateLimiter struct {
	mu       sync.Mutex
	counters map[string]*limitCounter
	limit    int
	burst    int
	window   time.Duration
}

type limitCounter struct {
	count     int
	resetAt   time.Time
}

func newSimpleRateLimiter(requestsPerMinute, burst int) *simpleRateLimiter {
	return &simpleRateLimiter{
		counters: make(map[string]*limitCounter),
		limit:    requestsPerMinute,
		burst:    burst,
		window:   time.Minute,
	}
}

func (l *simpleRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	counter, exists := l.counters[key]
	if !exists || now.After(counter.resetAt) {
		// New window
		l.counters[key] = &limitCounter{
			count:   1,
			resetAt: now.Add(l.window),
		}
		return true
	}

	// Check if burst allows it
	if counter.count < l.limit+l.burst {
		counter.count++
		return true
	}

	return false
}

// rateLimitMiddleware applies rate limiting to specific paths.
func (s *Server) rateLimitMiddleware(config map[string]RateLimitConfig) func(next http.Handler) http.Handler {
	// Create rate limiters for each configured path
	limiters := make(map[string]*simpleRateLimiter)
	for path, cfg := range config {
		limiters[path] = newSimpleRateLimiter(cfg.RequestsPerMinute, cfg.Burst)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Find matching rate limiter
			var limiter *simpleRateLimiter
			var matchedPath string
			for path := range limiters {
				fullPath := s.cfg.ExternalBasePath + path
				if r.URL.Path == fullPath || strings.HasPrefix(r.URL.Path, fullPath+"/") {
					limiter = limiters[path]
					matchedPath = path
					break
				}
			}

			if limiter != nil {
				// Get client IP key using deps.RealIP
				clientIP := "unknown"
				if d := deps.GetDeps(); d != nil && d.RealIP != nil {
					clientIP = d.RealIP.GetClientIPString(r)
				}

				if !limiter.allow(clientIP) {
					s.logger.Warn("rate limit exceeded",
						"path", matchedPath,
						"client_ip", clientIP,
					)
					w.Header().Set("Retry-After", "60")
					api.WriteTooManyRequests(w, "too many requests, please try again later")
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetSessionFromContext returns the session from request context.
func GetSessionFromContext(ctx context.Context) *identity.Session {
	session, _ := ctx.Value(SessionContextKey).(*identity.Session)
	return session
}

// GetUserFromContext returns the user from request context.
func GetUserFromContext(ctx context.Context) *identity.User {
	user, _ := ctx.Value(UserContextKey).(*identity.User)
	return user
}
