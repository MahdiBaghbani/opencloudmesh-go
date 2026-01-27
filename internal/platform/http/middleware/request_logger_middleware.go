// Package middleware provides always-on transport middleware for HTTP servers.
package middleware

import (
	"log/slog"
	"net/http"

	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
)

// RequestLoggerMiddleware attaches a request-scoped logger to the request context.
//
// This is server-layer wiring (Reva-like): it depends on realip.TrustedProxies and chi's RequestID.
// Keep it as a function (not a Server method) so it remains composable and easy to reuse.
//
// IMPORTANT: This middleware must run AFTER middleware.RequestID so that
// middleware.GetReqID(r.Context()) returns a non-empty value.
func RequestLoggerMiddleware(base *slog.Logger, trustedProxies *realip.TrustedProxies) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := chimw.GetReqID(r.Context())
			clientIP := "unknown"
			if trustedProxies != nil {
				clientIP = trustedProxies.GetClientIPString(r)
			}

			// Attach base request fields to the logger. These fields will be
			// inherited by the access log (AccessLogMiddleware) and any handler
			// that uses appctx.GetLogger(r.Context()).
			reqLogger := base.With(
				"request_id", reqID,
				"method", r.Method,
				"path", r.URL.Path, // path only, no query string
				"client_ip", clientIP,
			)

			ctx := appctx.WithLogger(r.Context(), reqLogger)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
