package wellknown

import (
	"encoding/json"
	"net/http"
	"net/url"

	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services"
)

// OCMProviderConfig holds OCM discovery configuration.
type OCMProviderConfig struct {
	Endpoint                       string `mapstructure:"endpoint"`        // This host's full URL (origin + base path)
	OCMPrefix                      string `mapstructure:"ocm_prefix"`      // Default: "ocm"
	Provider                       string `mapstructure:"provider"`        // Friendly name
	WebDAVRoot                     string `mapstructure:"webdav_root"`     // WebDAV path
	AdvertiseHTTPRequestSignatures bool   `mapstructure:"advertise_http_request_signatures"`

	TokenExchange struct {
		Enabled bool   `mapstructure:"enabled"`
		Path    string `mapstructure:"path"`
	} `mapstructure:"token_exchange"`
}

// ApplyDefaults sets default values for unset fields.
func (c *OCMProviderConfig) ApplyDefaults() {
	if c.OCMPrefix == "" {
		c.OCMPrefix = "ocm"
	}
	if c.Provider == "" {
		c.Provider = "OpenCloudMesh"
	}
	if c.WebDAVRoot == "" {
		c.WebDAVRoot = "/webdav/ocm/"
	}
	if c.TokenExchange.Path == "" {
		c.TokenExchange.Path = "token"
	}
}

type ocmHandler struct {
	data *spec.Discovery // static, computed once at init
	log  *slog.Logger
}

func newOCMHandler(c *OCMProviderConfig, deps *services.Deps, log *slog.Logger) (*ocmHandler, error) {
	c.ApplyDefaults()

	// Build static discovery data (Reva pattern: computed once, not at runtime)
	d := &spec.Discovery{
		Enabled:    false,
		APIVersion: "1.2.2",
		Provider:   c.Provider,
		Criteria:   []string{}, // Always present, serializes as [] when empty
	}

	if c.Endpoint == "" {
		return &ocmHandler{data: d, log: log}, nil
	}

	endpointURL, err := url.Parse(c.Endpoint)
	if err != nil {
		return &ocmHandler{data: d, log: log}, nil
	}

	// Build enabled discovery
	d.Enabled = true
	d.EndPoint, _ = url.JoinPath(c.Endpoint, c.OCMPrefix)

	// Resource types with WebDAV protocol
	d.ResourceTypes = []spec.ResourceType{{
		Name:       "file",
		ShareTypes: []string{"user"},
		Protocols:  map[string]string{"webdav": c.WebDAVRoot},
	}}

	// Capabilities (static, config-driven)
	capabilities := []string{}

	// Add public keys when available from SharedDeps
	if deps != nil && deps.KeyManager != nil {
		d.PublicKeys = []spec.PublicKey{{
			KeyID:        deps.KeyManager.GetKeyID(),
			PublicKeyPem: deps.KeyManager.GetPublicKeyPEM(),
			Algorithm:    "ed25519",
		}}
		capabilities = append(capabilities, "http-sig")
	}

	// Token exchange capability (only when enabled)
	if c.TokenExchange.Enabled {
		capabilities = append(capabilities, "exchange-token")
		// Build tokenEndPoint from config
		tokenPath := c.TokenExchange.Path
		if tokenPath == "" {
			tokenPath = "token"
		}
		d.TokenEndPoint, _ = url.JoinPath(c.Endpoint, c.OCMPrefix, tokenPath)
	}

	d.Capabilities = capabilities

	// Criteria (always present, serializes as [] when empty)
	if c.AdvertiseHTTPRequestSignatures {
		d.Criteria = append(d.Criteria, "http-request-signatures")
	}

	_ = endpointURL // parsed for validation only (keep for future use)
	return &ocmHandler{data: d, log: log}, nil
}

func (h *ocmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(h.data)
}
