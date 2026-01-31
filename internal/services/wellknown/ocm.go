package wellknown

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// APIVersionOverride allows overriding apiVersion based on User-Agent.
// Used for Nextcloud Server Crawler compatibility (expects apiVersion 1.1).
type APIVersionOverride struct {
	UserAgentContains string `mapstructure:"user_agent_contains"`
	APIVersion        string `mapstructure:"api_version"`
}

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

	// Invite accept dialog URL (absolute) for WAYF helpers
	InviteAcceptDialog string `mapstructure:"invite_accept_dialog"`
	AdvertiseInviteWAYF bool   `mapstructure:"advertise_invite_wayf"`

	// APIVersionOverrides allows overriding apiVersion based on User-Agent.
	// Used for Nextcloud Server Crawler compatibility.
	APIVersionOverrides []APIVersionOverride `mapstructure:"api_version_overrides"`
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
	data      *spec.Discovery      // static, computed once at init
	overrides []APIVersionOverride // User-Agent based apiVersion overrides
	log       *slog.Logger
}

func newOCMHandler(c *OCMProviderConfig, d *deps.Deps, log *slog.Logger) (*ocmHandler, error) {
	log = logutil.NoopIfNil(log)
	c.ApplyDefaults()

	// Build static discovery data (Reva pattern: computed once, not at runtime)
	disc := &spec.Discovery{
		Enabled:    false,
		APIVersion: "1.2.2",
		Provider:   c.Provider,
		Criteria:   []string{}, // Always present, serializes as [] when empty
	}

	if c.Endpoint == "" {
		return &ocmHandler{data: disc, overrides: c.APIVersionOverrides, log: log}, nil
	}

	endpointURL, err := url.Parse(c.Endpoint)
	if err != nil {
		return &ocmHandler{data: disc, overrides: c.APIVersionOverrides, log: log}, nil
	}

	// Build enabled discovery
	disc.Enabled = true
	disc.EndPoint, _ = url.JoinPath(c.Endpoint, c.OCMPrefix)

	// Resource types with WebDAV protocol
	disc.ResourceTypes = []spec.ResourceType{{
		Name:       "file",
		ShareTypes: []string{"user"},
		Protocols:  map[string]string{"webdav": c.WebDAVRoot},
	}}

	// Capabilities (static, config-driven)
	capabilities := []string{}

	// Add public keys when available from SharedDeps
	if d != nil && d.KeyManager != nil {
		disc.PublicKeys = []spec.PublicKey{{
			KeyID:        d.KeyManager.GetKeyID(),
			PublicKeyPem: d.KeyManager.GetPublicKeyPEM(),
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
		disc.TokenEndPoint, _ = url.JoinPath(c.Endpoint, c.OCMPrefix, tokenPath)
	}

	// Invite accept dialog (WAYF)
	if c.InviteAcceptDialog != "" {
		disc.InviteAcceptDialog = c.InviteAcceptDialog
		if c.AdvertiseInviteWAYF {
			capabilities = append(capabilities, "invite-wayf")
		}
	}

	disc.Capabilities = capabilities

	// Criteria (always present, serializes as [] when empty)
	if c.AdvertiseHTTPRequestSignatures {
		disc.Criteria = append(disc.Criteria, "http-request-signatures")
	}

	_ = endpointURL // parsed for validation only (keep for future use)
	return &ocmHandler{data: disc, overrides: c.APIVersionOverrides, log: log}, nil
}

func (h *ocmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := h.data

	// Check for User-Agent based apiVersion override (Nextcloud crawler compatibility)
	if len(h.overrides) > 0 {
		ua := r.Header.Get("User-Agent")
		for _, override := range h.overrides {
			if override.UserAgentContains != "" && strings.Contains(ua, override.UserAgentContains) {
				// Clone and override apiVersion
				clone := *data
				clone.APIVersion = override.APIVersion
				data = &clone
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}
