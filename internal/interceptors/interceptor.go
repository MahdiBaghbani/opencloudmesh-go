// Package interceptors provides cross-cutting HTTP middleware types and shared profile-config helpers.
package interceptors

import (
	"net/http"
)

// Middleware is an HTTP middleware function.
type Middleware func(http.Handler) http.Handler
