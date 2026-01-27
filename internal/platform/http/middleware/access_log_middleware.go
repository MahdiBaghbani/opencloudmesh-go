package middleware

import (
	"log/slog"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
)

// AccessLogMiddleware logs request information using slog.
// It uses the request-scoped logger from context (set by RequestLoggerMiddleware)
// which already has request_id, method, path, client_ip attached.
// The trustedProxies parameter is the fallback only (used when context logger is missing).
func AccessLogMiddleware(log *slog.Logger, trustedProxies *realip.TrustedProxies) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)

			defer func() {
				// Get logger from context (has request_id, method, path, client_ip)
				logger, ok := appctx.LoggerFromContext(r.Context())

				// Fallback: if context logger missing, recompute base fields
				if !ok {
					reqID := chimw.GetReqID(r.Context())
					clientIP := "unknown"
					if trustedProxies != nil {
						clientIP = trustedProxies.GetClientIPString(r)
					}
					logger = log.With(
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
}
