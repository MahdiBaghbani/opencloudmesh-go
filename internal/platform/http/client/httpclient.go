// Package client provides a safe outbound HTTP client with SSRF protections.
// See client.go for the concrete implementation.

package client

import (
	"context"
	"net/http"
)

// HTTPClient is the shared interface for outbound HTTP requests.
// Implemented by ContextClient; used by outgoing share/invite handlers and
// inbox invite handlers to avoid per-package interface duplication.
type HTTPClient interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}
