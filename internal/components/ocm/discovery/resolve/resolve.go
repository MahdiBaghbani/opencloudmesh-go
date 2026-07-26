// Package resolve derives OCM discovery provider configuration from service-local
// TOML plus narrow ResolveInputs supplied by wiring. Endpoint derivation requires
// a non-empty PublicOrigin in ResolveInputs.LocalIdentity.
package resolve

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// ProviderConfig holds OCM discovery configuration.
type ProviderConfig struct {
	Provider   string `mapstructure:"provider"`
	WebDAVRoot string `mapstructure:"webdav_root"`

	TokenExchange struct {
		Path string `mapstructure:"path"`
	} `mapstructure:"token_exchange"`

	InviteAcceptDialog string `mapstructure:"invite_accept_dialog"`
}

// ApplyDefaults sets default values for service-local fields only.
func (c *ProviderConfig) ApplyDefaults() {
	if c.Provider == "" {
		c.Provider = "OpenCloudMesh"
	}
}

// BuildInputs bundles the resolved discovery build params.
type BuildInputs struct {
	Params discovery.BuildParams
}

// Resolve applies service-local defaults, derives cross-cutting values from
// ResolveInputs and route inventory when not explicitly set in per-service TOML,
// maps the resolved code-flow facts into build params, and returns the resolved
// discovery build params.
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

	endPoint := projected.EndPoint
	webdavRoot := projected.WebDAVRoot
	tokenEndPoint := projected.TokenEndPoint
	inviteAcceptDialog := projected.InviteAcceptDialog

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

	if _, set := rawOCMProvider["invite_accept_dialog"]; set {
		inviteAcceptDialog = c.InviteAcceptDialog
	} else if inviteAcceptDialog != "" {
		c.InviteAcceptDialog = inviteAcceptDialog
	}

	advertiseHTTPSig := in.KeyManager != nil
	facts := resolveFacts(in)

	return BuildInputs{
		Params: discovery.BuildParams{
			Provider:               c.Provider,
			EndPoint:               endPoint,
			WebDAVRoot:             webdavRoot,
			WebDAVReceiveURI:       "relative",
			TokenEndPoint:          tokenEndPoint,
			InviteAcceptDialog:     inviteAcceptDialog,
			InvitesEnabled:         routeOpts.InvitesEnabled,
			WayfEnabled:            routeOpts.WayfEnabled,
			AdvertiseHTTPSig:       advertiseHTTPSig,
			TokenExchangeCapable:   facts.TokenExchangeCapable,
			RequiresTokenExchange:  facts.RequiresTokenExchange,
			RequiresHTTPSignatures: facts.RequiresHTTPRequestSignatures,
		},
	}
}

// resolveFacts derives the code-flow facts for the local discovery document.
// When a scope-gated resolver is wired, it is consulted with the local provider
// domain as the host and the reserved discovery view argument. The discovery
// view is accepted for signature stability but is not consulted by the current
// resolver logic. When no resolver is wired, the legacy CodeFlow.Evaluate path
// is used as a fallback.
func resolveFacts(in ResolveInputs) policy.Facts {
	if in.Resolver != nil {
		// The local provider domain is the host for LocalProfile resolution.
		// Global peer_compat knobs apply under global scope; under scoped they
		// apply only when the host is explicitly mapped.
		var disc policy.DiscoveryView = nil
		return in.Resolver.ResolveFacts(in.LocalIdentity.ProviderDomain, disc)
	}
	return in.CodeFlow.Evaluate()
}
