package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// loggingMiddleware logs request information using slog.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		defer func() {
			s.logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", middleware.GetReqID(r.Context()),
			)
		}()

		next.ServeHTTP(ww, r)
	})
}

// authMiddleware will be implemented in Phase 0b.
// For now, this is a placeholder that documents the auth gating pattern.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this path requires authentication
		if IsAuthRequired(r.URL.Path, s.cfg.ExternalBasePath) {
			// TODO: Implement actual auth check in Phase 0b
			// For now, we allow all requests through
		}
		next.ServeHTTP(w, r)
	})
}
