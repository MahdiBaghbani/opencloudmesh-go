// Package discovery implements OCM discovery endpoints and client. Type aliases wrap spec types.
package discovery

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

type (
	Discovery    = spec.Discovery
	ResourceType = spec.ResourceType
	PublicKey    = spec.PublicKey
)

// Handler serves OCM discovery. Legacy: wellknown now owns discovery; handler remains for SetPublicKeys.
type Handler struct {
	cfg        *config.Config
	mu         sync.RWMutex
	publicKeys []PublicKey
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{cfg: cfg}
}

// SetPublicKeys updates public keys for RFC 9421. Deprecated: wellknown computes keys at init.
func (h *Handler) SetPublicKeys(keys []PublicKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.publicKeys = keys
}

// GetDiscovery returns the discovery document. Deprecated: wellknown owns discovery; kept for tests.
func (h *Handler) GetDiscovery() *Discovery {
	h.mu.RLock()
	defer h.mu.RUnlock()

	endpoint := h.cfg.PublicOrigin
	if h.cfg.ExternalBasePath != "" {
		endpoint += h.cfg.ExternalBasePath
	}
	endpoint += "/ocm"

	capabilities := h.getCapabilities()
	criteria := h.getCriteria()
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
	return discovery
}

// getCapabilities returns the list of capabilities based on implemented phases.
// NOTE: Token exchange capability is now handled by the wellknown service.
func (h *Handler) getCapabilities() []string {
	var caps []string
	if len(h.publicKeys) > 0 {
		caps = append(caps, "http-sig")
	}
	return caps
}

// getCriteria returns criteria tokens. Non-nil slice so JSON serializes as [] when empty.
func (h *Handler) getCriteria() []string {
	criteria := []string{}
	if h.cfg.Signature.AdvertiseHTTPRequestSignatures {
		criteria = append(criteria, "http-request-signatures")
	}

	return criteria
}

func (h *Handler) getResourceTypes() []ResourceType {
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

func (h *Handler) WellKnownHandler() http.HandlerFunc {
	return h.ServeHTTP
}
