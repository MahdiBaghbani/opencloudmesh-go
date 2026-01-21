// Package discovery implements OCM discovery endpoints and client.
package discovery

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/spec"
)

// Type aliases for backward compatibility within this package.
// These allow existing code to use discovery.Discovery, discovery.ResourceType, etc.
type (
	Discovery    = spec.Discovery
	ResourceType = spec.ResourceType
	PublicKey    = spec.PublicKey
)

// Handler serves the OCM discovery endpoints.
// NOTE: This legacy handler is being phased out. The wellknown service now owns
// discovery endpoints. This handler remains temporarily for SetPublicKeys().
type Handler struct {
	cfg        *config.Config
	mu         sync.RWMutex
	publicKeys []PublicKey
}

// NewHandler creates a new discovery handler.
func NewHandler(cfg *config.Config) *Handler {
	return &Handler{cfg: cfg}
}

// SetPublicKeys updates the public keys for RFC 9421 signatures.
// This is called by the signature module when keys are generated/loaded.
// NOTE: This method is deprecated. The wellknown service computes keys at init.
func (h *Handler) SetPublicKeys(keys []PublicKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.publicKeys = keys
}

// GetDiscovery returns the current discovery document.
// NOTE: This method is deprecated. The wellknown service now owns discovery.
// This method remains for backward compatibility with existing tests.
func (h *Handler) GetDiscovery() *Discovery {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Build endpoint URL
	endpoint := h.cfg.ExternalOrigin
	if h.cfg.ExternalBasePath != "" {
		endpoint += h.cfg.ExternalBasePath
	}
	endpoint += "/ocm"

	// Build capabilities based on implemented phases
	capabilities := h.getCapabilities()

	// Build criteria based on config (always non-nil to serialize as [])
	criteria := h.getCriteria()

	// Build resource types
	resourceTypes := h.getResourceTypes()

	discovery := &Discovery{
		Enabled:       true,
		APIVersion:    "1.2.2",
		EndPoint:      endpoint,
		Provider:      "OpenCloudMesh",
		ResourceTypes: resourceTypes,
		Capabilities:  capabilities,
		Criteria:      criteria,
		PublicKeys:    h.publicKeys,
	}

	// NOTE: Token exchange is now handled by the wellknown service.
	// This legacy handler does not advertise token exchange.

	return discovery
}

// getCapabilities returns the list of capabilities based on implemented phases.
// NOTE: Token exchange capability is now handled by the wellknown service.
func (h *Handler) getCapabilities() []string {
	var caps []string

	// http-sig is added when signatures are implemented and keys are available
	if len(h.publicKeys) > 0 {
		caps = append(caps, "http-sig")
	}

	// NOTE: exchange-token is now advertised by the wellknown service, not here.

	return caps
}

// getCriteria returns the list of criteria tokens.
// Always returns a non-nil slice so it serializes as [] when empty.
func (h *Handler) getCriteria() []string {
	// Initialize as empty slice (not nil) to ensure JSON serializes as []
	criteria := []string{}

	// Add http-request-signatures when advertise is enabled
	if h.cfg.Signature.AdvertiseHTTPRequestSignatures {
		criteria = append(criteria, "http-request-signatures")
	}

	return criteria
}

// getResourceTypes returns the supported resource types.
func (h *Handler) getResourceTypes() []ResourceType {
	// Build WebDAV path
	webdavPath := h.cfg.ExternalBasePath + "/webdav/ocm/"

	return []ResourceType{
		{
			Name:       "file",
			ShareTypes: []string{"user"},
			Protocols: map[string]string{
				"webdav": webdavPath,
			},
		},
	}
}

// ServeHTTP handles GET requests for discovery.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	discovery := h.GetDiscovery()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(discovery)
}

// WellKnownHandler returns an http.HandlerFunc for /.well-known/ocm
func (h *Handler) WellKnownHandler() http.HandlerFunc {
	return h.ServeHTTP
}
