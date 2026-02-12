// Package interceptors provides cross-cutting HTTP middleware in a Reva-style registry pattern.
package interceptors

import (
	"log/slog"
	"net/http"
)

// Middleware is an HTTP middleware function.
type Middleware func(http.Handler) http.Handler

// NewInterceptor is the constructor function type for interceptors.
type NewInterceptor func(conf map[string]any, log *slog.Logger) (Middleware, error)
