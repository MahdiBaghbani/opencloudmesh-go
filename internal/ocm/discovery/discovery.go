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
	Enabled       bool           `json:"enabled"`
	APIVersion    string         `json:"apiVersion"`
	EndPoint      string         `json:"endPoint"`
	Provider      string         `json:"provider,omitempty"`
	ResourceTypes []ResourceType `json:"resourceTypes"`
	Capabilities  []string       `json:"capabilities,omitempty"`
	PublicKeys    []PublicKey    `json:"publicKeys,omitempty"`
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
func (h *Handler) SetPublicKeys(keys []PublicKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.publicKeys = keys
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

	// Build resource types
	resourceTypes := h.getResourceTypes()

	return &Discovery{
		Enabled:       true,
		APIVersion:    "1.2.2",
		EndPoint:      endpoint,
		Provider:      "OpenCloudMesh",
		ResourceTypes: resourceTypes,
		Capabilities:  capabilities,
		PublicKeys:    h.publicKeys,
	}
}

// getCapabilities returns the list of capabilities based on implemented phases.
func (h *Handler) getCapabilities() []string {
	var caps []string

	// http-sig is added in Phase C when signatures are implemented
	if len(h.publicKeys) > 0 {
		caps = append(caps, "http-sig")
	}

	// exchange-token is added in Phase I when token exchange is implemented
	// TODO: Add when token exchange is implemented

	return caps
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
