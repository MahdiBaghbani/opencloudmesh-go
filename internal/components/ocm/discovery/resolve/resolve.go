// Package resolve derives OCM discovery provider configuration from service-local
// TOML plus narrow ResolveInputs supplied by wiring. Endpoint derivation requires
// a non-empty PublicOrigin; per-service endpoint values in raw TOML always win.
package resolve

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// APIVersionOverride applies a peer-profile-bound apiVersion when the matched
// peer gate and User-Agent predicate both pass.
type APIVersionOverride struct {
	Profile           string `mapstructure:"profile"`
	UserAgentContains string `mapstructure:"user_agent_contains"`
	APIVersion        string `mapstructure:"api_version"`
}

// ProviderConfig holds OCM discovery configuration.
type ProviderConfig struct {
	Endpoint   string `mapstructure:"endpoint"`    // This host's full URL (origin + base path)
	OCMPrefix  string `mapstructure:"ocm_prefix"`  // Deprecated: route inventory owns protocol mount
	Provider   string `mapstructure:"provider"`    // Friendly name
	WebDAVRoot string `mapstructure:"webdav_root"` // WebDAV path

	TokenExchange struct {
		Enabled bool   `mapstructure:"enabled"`
		Path    string `mapstructure:"path"`
	} `mapstructure:"token_exchange"`

	// Invite accept dialog URL (absolute) for invite-accept UI
	InviteAcceptDialog  string `mapstructure:"invite_accept_dialog"`
	AdvertiseInviteWAYF bool   `mapstructure:"advertise_invite_wayf"`

	// APIVersionOverrides lists peer-profile-bound apiVersion overrides.
	APIVersionOverrides []APIVersionOverride `mapstructure:"api_version_overrides"`
}

// ApplyDefaults sets default values for service-local fields only.
func (c *ProviderConfig) ApplyDefaults() {
	if c.OCMPrefix == "" {
		c.OCMPrefix = "ocm"
	}
	if c.Provider == "" {
		c.Provider = "OpenCloudMesh"
	}
}

type localEvaluation struct {
	codeFlow               bool
	strict                 bool
	requiresHTTPSignatures bool
}

// BuildInputs bundles the resolved discovery build params with peer-profile-
// bound apiVersion overrides that passed compile-time binding validation.
type BuildInputs struct {
	Params    discovery.BuildParams
	Overrides []APIVersionOverride
}

// Resolve applies service-local defaults, derives cross-cutting values from
// ResolveInputs and route inventory when not explicitly set in per-service TOML,
// resolves policy-driven evaluation flags, and returns the resolved discovery
// build params plus any apiVersion overrides.
func Resolve(c *ProviderConfig, rawOCMProvider map[string]any, in ResolveInputs) BuildInputs {
	c.ApplyDefaults()

	routeOpts := in.RouteOpts
	if routeOpts.TokenExchangePath == "" {
		routeOpts.TokenExchangePath = in.TokenExchangePath
	}
	if routeOpts.TokenExchangePath == "" {
		routeOpts.TokenExchangePath = "token"
	}

	projected, hasProjection := spec.DeriveDiscoveryPaths(in.LocalIdentity, routeOpts)

	endpointExplicit := false
	if _, set := rawOCMProvider["endpoint"]; set {
		endpointExplicit = true
	}
	if _, set := rawOCMProvider["endpoint"]; !set && in.LocalIdentity.Origin != "" {
		c.Endpoint = in.LocalIdentity.EndpointBase
	}

	endPoint := projected.EndPoint
	webdavRoot := projected.WebDAVRoot
	tokenEndPoint := projected.TokenEndPoint
	inviteAcceptDialog := projected.InviteAcceptDialog

	if c.Endpoint != "" && (endpointExplicit || endPoint == "") {
		endPoint = spec.DeriveDiscoveryPathsFromEndpointBase(c.Endpoint, c.OCMPrefix, routeOpts).EndPoint
	}

	if _, set := rawOCMProvider["webdav_root"]; set {
		webdavRoot = c.WebDAVRoot
	} else if hasProjection {
		c.WebDAVRoot = webdavRoot
	} else if c.WebDAVRoot != "" {
		webdavRoot = c.WebDAVRoot
	}

	var rawTE map[string]any
	if te, ok := rawOCMProvider["token_exchange"].(map[string]any); ok {
		rawTE = te
	}
	if _, set := rawTE["path"]; !set && c.TokenExchange.Path == "" {
		c.TokenExchange.Path = routeOpts.TokenExchangePath
	} else if c.TokenExchange.Path != "" {
		routeOpts.TokenExchangePath = c.TokenExchange.Path
		if reproj, ok := spec.DeriveDiscoveryPaths(in.LocalIdentity, routeOpts); ok {
			tokenEndPoint = reproj.TokenEndPoint
		}
	}
	if _, set := rawTE["path"]; set || c.TokenExchange.Path != "" {
		if c.Endpoint != "" && (endpointExplicit || tokenEndPoint == "") {
			tokenEndPoint = spec.DeriveDiscoveryPathsFromEndpointBase(c.Endpoint, c.OCMPrefix, routeOpts).TokenEndPoint
		}
	} else if tokenEndPoint == "" && c.Endpoint != "" {
		tokenEndPoint = spec.DeriveDiscoveryPathsFromEndpointBase(c.Endpoint, c.OCMPrefix, routeOpts).TokenEndPoint
	}

	if _, set := rawOCMProvider["invite_accept_dialog"]; set {
		inviteAcceptDialog = c.InviteAcceptDialog
	} else if inviteAcceptDialog != "" {
		c.InviteAcceptDialog = inviteAcceptDialog
	}

	advertiseHTTPSig := in.KeyManager != nil

	var localEval localEvaluation
	if in.CodeFlow != nil {
		ev := in.CodeFlow.Evaluate()
		localEval = localEvaluation{
			codeFlow:               ev.TokenExchangeCapable,
			strict:                 ev.RequiresTokenExchange,
			requiresHTTPSignatures: ev.RequiresHTTPRequestSignatures,
		}
	} else {
		localEval = localEvaluation{codeFlow: c.TokenExchange.Enabled}
	}

	return BuildInputs{
		Params: discovery.BuildParams{
			Provider:               c.Provider,
			EndPoint:               endPoint,
			WebDAVRoot:             webdavRoot,
			TokenEndPoint:          tokenEndPoint,
			InviteAcceptDialog:     inviteAcceptDialog,
			AdvertiseInviteWAYF:    c.AdvertiseInviteWAYF,
			AdvertiseHTTPSig:       advertiseHTTPSig,
			TokenExchangeCapable:   localEval.codeFlow,
			RequiresTokenExchange:  localEval.strict,
			RequiresHTTPSignatures: localEval.requiresHTTPSignatures,
		},
		Overrides: filterAPIVersionOverrides(c.APIVersionOverrides, in.PeerContract),
	}
}
