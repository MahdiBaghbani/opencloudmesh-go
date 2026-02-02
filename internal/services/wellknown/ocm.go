package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
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

// ApplyDefaults sets default values for service-local fields only.
// Cross-cutting fields (endpoint, webdav_root, token_exchange, etc.) are
// derived from SharedDeps in newOCMHandler().
func (c *OCMProviderConfig) ApplyDefaults() {
	if c.OCMPrefix == "" {
		c.OCMPrefix = "ocm"
	}
	if c.Provider == "" {
		c.Provider = "OpenCloudMesh"
	}
}

type ocmHandler struct {
	data      *spec.Discovery      // static, computed once at init
	overrides []APIVersionOverride // User-Agent based apiVersion overrides
	log       *slog.Logger
}

// newOCMHandler builds the static OCM discovery handler.
// rawOCMProvider is the raw config map from TOML (used for key-presence
// detection so we can distinguish "not set" from "explicitly set to zero").
func newOCMHandler(c *OCMProviderConfig, rawOCMProvider map[string]any, d *deps.Deps, log *slog.Logger) (*ocmHandler, error) {
	log = logutil.NoopIfNil(log)
	c.ApplyDefaults()

	// Derive cross-cutting values from SharedDeps config when not explicitly
	// set in per-service TOML. Per-service TOML wins when a key is present
	// in the raw map (even if zero-valued).
	if d != nil && d.Config != nil {
		if _, set := rawOCMProvider["endpoint"]; !set {
			c.Endpoint = d.Config.PublicOrigin + d.Config.ExternalBasePath
		}

		if _, set := rawOCMProvider["webdav_root"]; !set {
			if d.Config.ExternalBasePath != "" {
				c.WebDAVRoot = d.Config.ExternalBasePath + "/webdav/ocm/"
			} else {
				c.WebDAVRoot = "/webdav/ocm/"
			}
		}

		if _, set := rawOCMProvider["advertise_http_request_signatures"]; !set {
			c.AdvertiseHTTPRequestSignatures = d.Config.Signature.AdvertiseHTTPRequestSignatures
		}

		// Token exchange derivation
		var rawTE map[string]any
		if te, ok := rawOCMProvider["token_exchange"].(map[string]any); ok {
			rawTE = te
		}
		if _, set := rawTE["enabled"]; !set {
			c.TokenExchange.Enabled = d.Config.TokenExchangeEnabled()
		}
		if _, set := rawTE["path"]; !set {
			c.TokenExchange.Path = d.Config.TokenExchange.Path
			if c.TokenExchange.Path == "" {
				c.TokenExchange.Path = "token"
			}
		}

		// API version overrides for interop/dev mode (Nextcloud crawler compat)
		if _, set := rawOCMProvider["api_version_overrides"]; !set {
			mode, _ := config.ParseMode(d.Config.Mode)
			if mode == config.ModeInterop || mode == config.ModeDev {
				c.APIVersionOverrides = []APIVersionOverride{{
					UserAgentContains: "Nextcloud Server Crawler",
					APIVersion:        "1.1",
				}}
			}
		}
	}

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

	// Unconditional capabilities (always advertised per OCM-API spec)
	capabilities = append(capabilities, "invites", "webdav-uri", "protocol-object", "notifications")

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
