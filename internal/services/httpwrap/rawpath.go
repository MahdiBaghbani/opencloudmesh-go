// Package httpwrap provides HTTP handler wrappers for service layer use.
package httpwrap

import "net/http"

// ClearRawPath wraps a handler and clears r.URL.RawPath before routing.
// This matches Reva's pattern in internal/http/services/sciencemesh/sciencemesh.go
// and prevents chi routing mismatches on percent-encoded path segments.
func ClearRawPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.RawPath = ""
		next.ServeHTTP(w, r)
	})
}
