// Package discovery implements OCM discovery endpoints and client.
package discovery

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
)

// Discovery represents the OCM discovery response.
// See OCM-API spec: https://github.com/cs3org/OCM-API/blob/develop/spec.yaml
type Discovery struct {
	Enabled        bool           `json:"enabled"`
	APIVersion     string         `json:"apiVersion"`
	EndPoint       string         `json:"endPoint"`
	Provider       string         `json:"provider,omitempty"`
	ResourceTypes  []ResourceType `json:"resourceTypes"`
	Capabilities   []string       `json:"capabilities,omitempty"`
	Criteria       []string       `json:"criteria"` // Always present, serializes as [] when empty
	PublicKeys     []PublicKey    `json:"publicKeys,omitempty"`
	TokenEndPoint  string         `json:"tokenEndPoint,omitempty"` // Required when exchange-token capability is advertised
}

// ResourceType describes a supported resource type.
type ResourceType struct {
	Name       string              `json:"name"`
	ShareTypes []string            `json:"shareTypes"`
	Protocols  map[string]string   `json:"protocols"`
}

// PublicKey represents a public key for RFC 9421 HTTP signatures.
type PublicKey struct {
	KeyID        string `json:"keyId"`
	PublicKeyPem string `json:"publicKeyPem"`
	Algorithm    string `json:"algorithm,omitempty"`
}

// Handler serves the OCM discovery endpoints.
type Handler struct {
	cfg                  *config.Config
	mu                   sync.RWMutex
	publicKeys           []PublicKey
	tokenExchangeEnabled bool
}

// NewHandler creates a new discovery handler.
func NewHandler(cfg *config.Config) *Handler {
	return &Handler{cfg: cfg}
}

// SetPublicKeys updates the public keys for RFC 9421 signatures.
// This is called by the signature module when keys are generated/loaded.
func (h *Handler) SetPublicKeys(keys []PublicKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.publicKeys = keys
}

// SetTokenExchangeEnabled enables or disables the exchange-token capability.
// When enabled, the discovery response includes tokenEndPoint.
func (h *Handler) SetTokenExchangeEnabled(enabled bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tokenExchangeEnabled = enabled
}

// IsTokenExchangeEnabled returns whether token exchange is enabled.
func (h *Handler) IsTokenExchangeEnabled() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.tokenExchangeEnabled
}

// GetDiscovery returns the current discovery document.
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

	// Add tokenEndPoint when exchange-token capability is advertised
	if h.tokenExchangeEnabled {
		tokenEndpoint := h.cfg.ExternalOrigin
		if h.cfg.ExternalBasePath != "" {
			tokenEndpoint += h.cfg.ExternalBasePath
		}
		tokenEndpoint += "/ocm/token"
		discovery.TokenEndPoint = tokenEndpoint
	}

	return discovery
}

// getCapabilities returns the list of capabilities based on implemented phases.
func (h *Handler) getCapabilities() []string {
	var caps []string

	// http-sig is added when signatures are implemented and keys are available
	if len(h.publicKeys) > 0 {
		caps = append(caps, "http-sig")
	}

	// exchange-token is added when token exchange is implemented and enabled
	if h.tokenExchangeEnabled {
		caps = append(caps, "exchange-token")
	}

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
