// Package resolve derives OCM discovery provider configuration from service-local
// TOML plus narrow ResolveInputs supplied by wiring. Endpoint derivation requires
// a non-empty PublicOrigin; per-service endpoint values in raw TOML always win.
package resolve

import (
	"github.com/mitchellh/mapstructure"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
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
// derived from ResolveInputs in Resolve().
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
// ResolveInputs when not explicitly set in per-service TOML, resolves public keys
// and policy-driven evaluation flags, and returns the resolved discovery build
// params plus any apiVersion overrides. It mutates c in place to record the
// derived values (preserving the prior service-layer behavior).
//
// rawOCMProvider is the raw config map from TOML (used for key-presence
// detection so we can distinguish "not set" from "explicitly set to zero").
func Resolve(c *ProviderConfig, rawOCMProvider map[string]any, in ResolveInputs) BuildInputs {
	c.ApplyDefaults()

	tokenExchangePath := in.TokenExchangePath
	if tokenExchangePath == "" {
		tokenExchangePath = "token"
	}

	// Derive cross-cutting values from ResolveInputs when not explicitly
	// set in per-service TOML. Per-service TOML wins when a key is present
	// in the raw map (even if zero-valued). Endpoint needs PublicOrigin so
	// we never synthesize a relative or origin-less URL.
	if _, set := rawOCMProvider["endpoint"]; !set && in.PublicOrigin != "" {
		c.Endpoint = in.PublicOrigin + in.ExternalBasePath
	}

	if _, set := rawOCMProvider["webdav_root"]; !set {
		if in.ExternalBasePath != "" {
			c.WebDAVRoot = in.ExternalBasePath + "/webdav/ocm/"
		} else {
			c.WebDAVRoot = "/webdav/ocm/"
		}
	}

	var rawTE map[string]any
	if te, ok := rawOCMProvider["token_exchange"].(map[string]any); ok {
		rawTE = te
	}
	if _, set := rawTE["path"]; !set && c.TokenExchange.Path == "" {
		c.TokenExchange.Path = tokenExchangePath
	}

	if _, set := rawOCMProvider["api_version_overrides"]; !set {
		if in.RuntimePolicy != nil && in.RuntimePolicy.AllowsGlobalCompatibilityDefaults() {
			c.APIVersionOverrides = []APIVersionOverride{{
				UserAgentContains: "Nextcloud Server Crawler",
				APIVersion:        "1.1",
			}}
		}
	}

	if _, set := rawOCMProvider["invite_accept_dialog"]; !set && in.UIWayfEnabled && in.PublicOrigin != "" {
		c.InviteAcceptDialog = in.PublicOrigin + in.ExternalBasePath + "/ui/accept-invite"
	}

	var publicKeys []discovery.PublicKey
	if in.KeyManager != nil {
		publicKeys = []discovery.PublicKey{{
			KeyID:        in.KeyManager.GetKeyID(),
			PublicKeyPem: in.KeyManager.GetPublicKeyPEM(),
			Algorithm:    "ed25519",
		}}
	}

	var localEval localEvaluation
	if in.OpenCloudMeshPolicy != nil {
		ev := in.OpenCloudMeshPolicy.Evaluate()
		localEval = localEvaluation{codeFlow: ev.TokenExchangeCapable, strict: ev.RequiresTokenExchange}
	} else {
		localEval = localEvaluation{codeFlow: c.TokenExchange.Enabled}
	}
	if in.RuntimePolicy != nil {
		localEval.requiresHTTPSignatures = in.RuntimePolicy.Evaluate().Signature.RequiresHTTPRequestSignatures
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

// UIWayfEnabledFromConfig returns whether the UI service has WAYF enabled.
func UIWayfEnabledFromConfig(uiRaw map[string]any) bool {
	if uiRaw == nil {
		return false
	}
	var probe uiWayfProbe
	_ = mapstructure.Decode(uiRaw, &probe)
	return probe.Wayf.Enabled
}
