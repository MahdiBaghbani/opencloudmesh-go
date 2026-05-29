// Package resolve derives the cross-cutting inputs for an OCM discovery
// document from shared deps and the raw per-service config, then hands the
// resolved values to the discovery builder. It lives near the discovery
// component (rather than inside it) because it depends on the platform deps
// layer, which itself imports discovery; keeping resolution here avoids an
// import cycle while pulling this logic out of the service layer.
package resolve

import (
	"log/slog"

	"github.com/mitchellh/mapstructure"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// uiWayfProbe is a minimal struct for peeking at the UI service's WAYF config.
// Used to auto-derive inviteAcceptDialog when WAYF is enabled but
// invite_accept_dialog is not explicitly configured.
type uiWayfProbe struct {
	Wayf struct {
		Enabled bool `mapstructure:"enabled"`
	} `mapstructure:"wayf"`
}

// APIVersionOverride allows overriding apiVersion based on User-Agent.
// Used for Nextcloud Server Crawler compatibility (expects apiVersion 1.1).
type APIVersionOverride struct {
	UserAgentContains string `mapstructure:"user_agent_contains"`
	APIVersion        string `mapstructure:"api_version"`
}

// ProviderConfig holds OCM discovery configuration.
type ProviderConfig struct {
	Endpoint   string `mapstructure:"endpoint"`    // This host's full URL (origin + base path)
	OCMPrefix  string `mapstructure:"ocm_prefix"`  // Default: "ocm"
	Provider   string `mapstructure:"provider"`    // Friendly name
	WebDAVRoot string `mapstructure:"webdav_root"` // WebDAV path

	TokenExchange struct {
		Enabled bool   `mapstructure:"enabled"`
		Path    string `mapstructure:"path"`
	} `mapstructure:"token_exchange"`

	// Invite accept dialog URL (absolute) for WAYF helpers
	InviteAcceptDialog  string `mapstructure:"invite_accept_dialog"`
	AdvertiseInviteWAYF bool   `mapstructure:"advertise_invite_wayf"`

	// APIVersionOverrides allows overriding apiVersion based on User-Agent.
	// Used for Nextcloud Server Crawler compatibility.
	APIVersionOverrides []APIVersionOverride `mapstructure:"api_version_overrides"`
}

// ApplyDefaults sets default values for service-local fields only.
// Cross-cutting fields (endpoint, webdav_root, token_exchange, etc.) are
// derived from SharedDeps in Resolve().
func (c *ProviderConfig) ApplyDefaults() {
	if c.OCMPrefix == "" {
		c.OCMPrefix = "ocm"
	}
	if c.Provider == "" {
		c.Provider = "OpenCloudMesh"
	}
}

// localEvaluation is a local snapshot of the canonical evaluator output.
type localEvaluation struct {
	codeFlow               bool
	strict                 bool
	requiresHTTPSignatures bool
}

// BuildInputs bundles the resolved discovery build params with the
// User-Agent based apiVersion overrides derived during resolution.
type BuildInputs struct {
	Params    discovery.BuildParams
	Overrides []APIVersionOverride
}

// Resolve applies service-local defaults, derives cross-cutting values from
// SharedDeps when not explicitly set in per-service TOML, resolves public keys
// and policy-driven evaluation flags, and returns the resolved discovery build
// params plus any apiVersion overrides. It mutates c in place to record the
// derived values (preserving the prior service-layer behavior).
//
// rawOCMProvider is the raw config map from TOML (used for key-presence
// detection so we can distinguish "not set" from "explicitly set to zero").
func Resolve(c *ProviderConfig, rawOCMProvider map[string]any, d *deps.Deps, log *slog.Logger) BuildInputs {
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

		// Token exchange path derivation. Capability enablement belongs to the
		// canonical OCM policy when SharedDeps provides it.
		var rawTE map[string]any
		if te, ok := rawOCMProvider["token_exchange"].(map[string]any); ok {
			rawTE = te
		}
		if _, set := rawTE["path"]; !set {
			c.TokenExchange.Path = d.Config.TokenExchange.Path
			if c.TokenExchange.Path == "" {
				c.TokenExchange.Path = "token"
			}
		}

		// API version overrides for unbounded compatibility posture
		// (Nextcloud crawler compat).
		if _, set := rawOCMProvider["api_version_overrides"]; !set {
			if d.RuntimePolicy != nil && d.RuntimePolicy.AllowsGlobalCompatibilityDefaults() {
				c.APIVersionOverrides = []APIVersionOverride{{
					UserAgentContains: "Nextcloud Server Crawler",
					APIVersion:        "1.1",
				}}
			}
		}

		// Auto-derive inviteAcceptDialog when WAYF is enabled and the field
		// is not explicitly set in TOML. Peek at the UI service's config to
		// check WAYF enablement. This cross-service config read is acceptable
		// because discovery data is static (computed once at construction).
		if _, set := rawOCMProvider["invite_accept_dialog"]; !set {
			var probe uiWayfProbe
			if uiRaw := d.Config.HTTP.Services["ui"]; uiRaw != nil {
				_ = mapstructure.Decode(uiRaw, &probe)
			}
			if probe.Wayf.Enabled {
				c.InviteAcceptDialog = d.Config.PublicOrigin + d.Config.ExternalBasePath + "/ui/accept-invite"
			}
		}
	}

	// Resolve public keys from SharedDeps when available.
	var publicKeys []discovery.PublicKey
	if d != nil && d.KeyManager != nil {
		publicKeys = []discovery.PublicKey{{
			KeyID:        d.KeyManager.GetKeyID(),
			PublicKeyPem: d.KeyManager.GetPublicKeyPEM(),
			Algorithm:    "ed25519",
		}}
	}

	// Token exchange capability is owned by OpenCloudMeshPolicy when available.
	var localEval localEvaluation
	if d != nil && d.OpenCloudMeshPolicy != nil {
		ev := d.OpenCloudMeshPolicy.Evaluate()
		localEval = localEvaluation{codeFlow: ev.TokenExchangeCapable, strict: ev.RequiresTokenExchange}
	} else {
		// Keep narrow tests usable when they seed the service-local config
		// directly, but do not silently re-derive this from shared raw config.
		localEval = localEvaluation{codeFlow: c.TokenExchange.Enabled}
	}
	if d != nil && d.RuntimePolicy != nil {
		localEval.requiresHTTPSignatures = d.RuntimePolicy.Evaluate().Signature.RequiresHTTPRequestSignatures
	}

	return BuildInputs{
		Params: discovery.BuildParams{
			Provider:               c.Provider,
			Endpoint:               c.Endpoint,
			OCMPrefix:              c.OCMPrefix,
			WebDAVRoot:             c.WebDAVRoot,
			TokenExchangePath:      c.TokenExchange.Path,
			InviteAcceptDialog:     c.InviteAcceptDialog,
			AdvertiseInviteWAYF:    c.AdvertiseInviteWAYF,
			PublicKeys:             publicKeys,
			TokenExchangeCapable:   localEval.codeFlow,
			RequiresTokenExchange:  localEval.strict,
			RequiresHTTPSignatures: localEval.requiresHTTPSignatures,
		},
		Overrides: c.APIVersionOverrides,
	}
}
