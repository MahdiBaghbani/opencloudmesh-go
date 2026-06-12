package server

import (
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
)

// ServerDeps holds dependencies injected into the HTTP server at construction.
type ServerDeps struct {
	RealIP   *realip.TrustedProxies
	AuthGate func(requireAuth func(string) bool) func(http.Handler) http.Handler
}
