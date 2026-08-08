// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package config provides configuration loading and validation.
package config

import (
	"maps"
	"net/url"
	"strings"
)

// Config holds the server configuration.
type Config struct {
	// Mode selects a preset bundle: strict or dev.
	Mode string `toml:"mode"`

	// PublicOrigin is the public origin (scheme + host + port) for this instance.
	// Example: "https://localhost:9200"
	PublicOrigin string `toml:"public_origin"`

	// ExternalBasePath is the optional path prefix for app endpoints.
	// The root-only well-known discovery endpoint (/.well-known/ocm) is
	// never under this path; the local JWKS route (<endPoint>/jwks) is
	// mounted under the OCM service and does move with this path.
	// Example: "/ocm" or empty string
	ExternalBasePath string `toml:"external_base_path"`

	// ListenAddr is the address to listen on.
	// Example: ":9200"
	ListenAddr string `toml:"listen_addr"`

	// Server holds server-level settings.
	Server ServerConfig `toml:"server"`

	// TLS configuration
	TLS TLSConfig `toml:"tls"`

	// OutboundHTTP configuration
	OutboundHTTP OutboundHTTPConfig `toml:"outbound_http"`

	// Signature configuration
	Signature SignatureConfig `toml:"signature"`

	// Cache configuration
	Cache CacheConfig `toml:"cache"`

	// Peer trust configuration
	PeerTrust PeerTrustConfig `toml:"peer_trust"`

	// Logging configuration
	Logging LoggingConfig `toml:"logging"`

	// TokenExchange configuration
	TokenExchange TokenExchangeConfig `toml:"token_exchange"`

	// HTTP holds per-service HTTP configuration (Reva-style).
	HTTP HTTPConfig `toml:"http"`

	// Persistence holds persistence backend settings.
	Persistence PersistenceConfig `toml:"persistence"`

	// OCM holds OCM-specific settings.
	OCM OCMConfig `toml:"ocm"`
}

// OCMConfig holds OCM-specific settings.
type OCMConfig struct {
	// CompatibilityScope selects global vs scoped peer-compat leniency.
	// Default: global. This is ocmgo-internal policy, not an OCM spec field.
	CompatibilityScope CompatibilityScope `toml:"compatibility_scope"`

	Discovery   DiscoveryConfig   `toml:"discovery"`
	CodeFlow    CodeFlowConfig    `toml:"code_flow"`
	PeerMapping PeerMappingConfig `toml:"peer_compat"`
	Invite      *InviteConfig     `toml:"invite"`
}

// InviteConfig holds invite-exchange enforcement settings under [ocm.invite].
// This is independent of peer_trust.enabled: must-invite gates inbound share
// creation on an exchanged invite, not on peer-trust membership.
type InviteConfig struct {
	// EnforceMustInvite requires an exchanged invite before accepting a share
	// creation notification (IETF-OCM:
	// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L763-L765).
	// Nil means enabled (the default); explicit false is the legacy opt-out.
	EnforceMustInvite *bool `toml:"enforce_must_invite"`
}

// MustInviteEnforced reports whether inbound shares require an exchanged
// invite. Unset configuration evaluates to enabled.
func (c OCMConfig) MustInviteEnforced() bool {
	if c.Invite == nil || c.Invite.EnforceMustInvite == nil {
		return true
	}

	return *c.Invite.EnforceMustInvite
}

// DiscoveryConfig holds inbound peer discovery validation settings.
type DiscoveryConfig struct {
	// PeerAPIVersionPolicy selects accept policy: accept-any, exact, at-least-1.4.
	PeerAPIVersionPolicy string `toml:"peer_api_version_policy"`

	// PeerAPIVersionWarn selects warning behavior: any-diff, lower-only, none.
	PeerAPIVersionWarn string `toml:"peer_api_version_warn"`
}

// CodeFlowConfig holds relaxable OCM code-flow knobs under [ocm.code_flow].
// Unset (nil) means inherit/strict default; false relaxes; true enforces.
type CodeFlowConfig struct {
	IncludesTokenExchangeRequirement *bool `toml:"includes_token_exchange_requirement"`
	RequiresTokenExchangeRequirement *bool `toml:"requires_token_exchange_requirement"`
	RequiresHTTPRequestSignatures    *bool `toml:"requires_http_request_signatures"`
}

// PersistenceConfig holds persistence backend settings.
type PersistenceConfig struct {
	// Backend selects the persistence backend: memory, json, sqlite, mirror.
	// Preset default: strict uses sqlite; dev uses memory (see presets.go).
	Backend string `toml:"backend"`

	// DataDir is the data directory for durable backends (json, sqlite, mirror).
	// Required when backend is json, sqlite, or mirror.
	DataDir string `toml:"data_dir"`
}

// HTTPConfig holds per-service HTTP configuration.
// Services are configured under [http.services.<svcname>].
// Interceptors are configured under [http.interceptors.<name>].
type HTTPConfig struct {
	// Services maps service names to their raw config maps.
	// Each service decodes its own config via cfg.Decode() with Setter interface.
	Services map[string]map[string]any `toml:"services"`

	// Interceptors maps interceptor names to their raw config maps.
	// Ratelimit profiles live at [http.interceptors.ratelimit.profiles.<name>].
	// Per-service opt-in is [http.services.<svc>.ratelimit] with profile = "<name>".
	Interceptors map[string]map[string]any `toml:"interceptors"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	// Level is the minimum log level: trace, debug, info, warn, error.
	// Default: info in strict mode, debug in dev mode.
	Level string `toml:"level"`
}

// TokenExchangeConfig holds token exchange settings.
type TokenExchangeConfig struct {
	// Path is the token exchange endpoint path (relative to /ocm/).
	// Default: "token"
	Path string `toml:"path"`
}

// CacheConfig holds cache settings.
type CacheConfig struct {
	// Driver is the cache driver name: "memory" (default). Other drivers may fail validation.
	Driver string `toml:"driver"`

	// Drivers holds per-driver configuration (Reva-style).
	// Example: [cache.drivers.memory] ...
	Drivers map[string]any `toml:"drivers"`
}

// PeerTrustConfig holds peer trust settings.
type PeerTrustConfig struct {
	// Enabled enables peer trust features. Default: false.
	Enabled bool `toml:"enabled"`

	// ConfigPaths is a list of paths to JSON trust group config files.
	// Required when enabled.
	ConfigPaths []string `toml:"config_paths"`

	// Policy contains trust policy settings.
	Policy PeerTrustPolicyConfig `toml:"policy"`

	// MembershipCache contains membership cache settings.
	MembershipCache PeerTrustMembershipCacheConfig `toml:"membership_cache"`
}

// PeerTrustPolicyConfig holds peer trust policy settings.
type PeerTrustPolicyConfig struct {
	// AllowList is a list of always-allowed hosts.
	AllowList []string `toml:"allow_list"`

	// DenyList is a list of always-denied hosts.
	DenyList []string `toml:"deny_list"`
}

// PeerTrustMembershipCacheConfig holds membership cache settings.
type PeerTrustMembershipCacheConfig struct {
	// TTLSeconds is the cache TTL in seconds. Default: 21600 (6 hours).
	TTLSeconds int `toml:"ttl_seconds"`

	// MaxStaleSeconds is the max staleness before treating as unavailable. Default: 604800 (7 days).
	MaxStaleSeconds int `toml:"max_stale_seconds"`
}

// ServerConfig holds server-level settings.
type ServerConfig struct {
	// TrustedProxies is a list of CIDR ranges for trusted reverse proxies.
	// X-Forwarded-* headers are only honored from these addresses.
	// Default: ["127.0.0.0/8", "::1/128"]
	TrustedProxies []string `toml:"trusted_proxies"`

	// BootstrapAdmin holds super admin bootstrap configuration.
	BootstrapAdmin BootstrapAdminConfig `toml:"bootstrap_admin"`
}

// BootstrapAdminConfig holds bootstrap admin credentials.
type BootstrapAdminConfig struct {
	// Username for the super admin. Default: "admin"
	Username string `toml:"username"`

	// Password for the super admin. If empty on first boot, a random password is generated.
	Password string `toml:"password"`

	// CredentialFile is where an auto-generated bootstrap password is written.
	// Relative paths resolve against the process working directory.
	CredentialFile string `toml:"password_file"`
}

// SignatureConfig holds HTTP signature settings.
type SignatureConfig struct {
	// KeyPath is where the signing private key is stored
	KeyPath string `toml:"key_path"`

	// Label is the RFC 9421 signature dictionary label (default: ocm).
	Label string `toml:"label"`

	// KidFragment is the host#fragment suffix for local JWKS kid (default: key1).
	KidFragment string `toml:"kid_fragment"`

	// CreatedMaxAgeSeconds is the maximum signature age verifiers accept.
	CreatedMaxAgeSeconds int `toml:"created_max_age_seconds"`

	// CreatedMaxSkewSeconds is the maximum clock skew into the future verifiers accept.
	CreatedMaxSkewSeconds int `toml:"created_max_skew_seconds"`

	// AllowedAlgorithms lists permitted asymmetric RFC 9421 algorithms for
	// inbound verification and outbound SignRequest. The local private key
	// (default Ed25519) still performs signing; this list must include that
	// key's algorithm or SignRequest fails before the request is sent.
	AllowedAlgorithms []string `toml:"allowed_algorithms"`

	// JwksURI optionally overrides the local JWKS URL advertised in
	// discovery. Empty derives it from the route inventory as
	// <endPoint>/jwks.
	JwksURI string `toml:"jwks_uri"`
}

// TLSConfig holds TLS-related settings.
type TLSConfig struct {
	// Mode is one of: off, static, selfsigned, acme
	Mode string `toml:"mode"`

	// CertFile and KeyFile for static mode
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`

	// HTTPPort for HTTP listener (used for ACME challenges and redirects)
	HTTPPort int `toml:"http_port"`

	// HTTPSPort for HTTPS listener
	HTTPSPort int `toml:"https_port"`

	// SelfSignedDir is where self-signed certs are stored
	SelfSignedDir string `toml:"self_signed_dir"`

	// TLSDir optionally re-roots default paths (self_signed_dir, acme.storage_dir, signature.key_path).
	// When set, paths are derived unless explicitly defined in TOML. Default: empty (unset).
	TLSDir string `toml:"tls_dir"`

	// ACME configuration
	ACME ACMEConfig `toml:"acme"`
}

// ACMEConfig holds ACME/Let's Encrypt settings.
type ACMEConfig struct {
	// Email for ACME registration
	Email string `toml:"email"`

	// Domain is the domain to obtain a certificate for
	Domain string `toml:"domain"`

	// Directory is the ACME server URL (default: Let's Encrypt production)
	Directory string `toml:"directory"`

	// StorageDir is where ACME certificates and account info are stored
	StorageDir string `toml:"storage_dir"`

	// UseStaging uses Let's Encrypt staging (for testing)
	UseStaging bool `toml:"use_staging"`
}

// SSRFRoutePolicyConfig defines a named SSRF route policy with explicit
// allow-lists for private destinations.
type SSRFRoutePolicyConfig struct {
	// AllowPrivateHostSuffixes lists host suffixes permitted for private routing.
	AllowPrivateHostSuffixes []string `toml:"allow_private_host_suffixes"`

	// AllowPrivateCIDRs lists CIDR ranges permitted for private routing.
	// Catch-all CIDRs (0.0.0.0/0, ::/0) are rejected by route-policy validation.
	AllowPrivateCIDRs []string `toml:"allow_private_cidrs"`

	// AllowedPorts restricts which destination ports are permitted.
	AllowedPorts []int `toml:"allowed_ports"`

	// AllowIPLiterals permits direct IP address targets when true.
	AllowIPLiterals bool `toml:"allow_ip_literals"`
}

// SSRFConfig holds SSRF protection settings for outbound HTTP requests.
type SSRFConfig struct {
	// Mode is one of: strict, off.
	Mode string `toml:"mode"`

	// RoutePolicy names the active route policy from RoutePolicies.
	// When set the named policy must exist in RoutePolicies.
	RoutePolicy string `toml:"route_policy"`

	// RoutePolicies maps policy names to their definitions.
	RoutePolicies map[string]SSRFRoutePolicyConfig `toml:"route_policies"`
}

// OutboundHTTPConfig holds settings for outbound HTTP requests.
type OutboundHTTPConfig struct {
	// SSRF holds SSRF protection settings.
	// Configure via [outbound_http.ssrf] in TOML.
	SSRF SSRFConfig `toml:"ssrf"`

	// TimeoutMS is the overall request timeout in milliseconds
	TimeoutMS int `toml:"timeout_ms"`

	// ConnectTimeoutMS is the connection timeout in milliseconds
	ConnectTimeoutMS int `toml:"connect_timeout_ms"`

	// MaxRedirects is the maximum number of redirects to follow
	MaxRedirects int `toml:"max_redirects"`

	// MaxResponseBytes is the maximum response body size
	MaxResponseBytes int64 `toml:"max_response_bytes"`

	// InsecureSkipVerify disables TLS verification (dev-only)
	InsecureSkipVerify bool `toml:"insecure_skip_verify"`

	// TLSRootCAFile is a PEM file of root CAs for outbound TLS verification.
	TLSRootCAFile string `toml:"tls_root_ca_file"`

	// TLSRootCADir is a directory of .pem/.crt files for outbound TLS root CAs.
	TLSRootCADir string `toml:"tls_root_ca_dir"`

	// ProxyURL is an optional HTTP/HTTPS proxy for all outbound requests.
	// Must be an absolute http or https URL with no userinfo.
	// When set, the proxy host is operator-trusted; private and loopback
	// addresses are permitted.
	// When set, proxy_url takes precedence over use_env_fallback; the
	// explicit URL is used and environment variables are not consulted.
	ProxyURL string `toml:"proxy_url"`

	// UseEnvFallback (config key use_env_fallback) enables reading
	// HTTP_PROXY/HTTPS_PROXY/NO_PROXY from the environment when proxy_url is
	// not set. Default: false in all presets. Set to true to opt in to
	// ambient proxy discovery, or set the
	// OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK environment variable.
	UseEnvFallback bool `toml:"use_env_fallback"`
}

// OutboundHTTPConfigStrict returns strict outbound HTTP config for production.
// UseEnvFallback (use_env_fallback) is false so programmatic callers do not
// inherit ambient env proxy settings unless explicitly configured.
func OutboundHTTPConfigStrict() OutboundHTTPConfig {
	cfg := DefaultOutboundHTTP()
	cfg.UseEnvFallback = false

	return cfg
}

// BuildServiceConfig returns the raw service config map for a given service name.
// Returns nil if the service is not configured in [http.services.<name>].
func (c *Config) BuildServiceConfig(serviceName string) map[string]any {
	if c.HTTP.Services == nil {
		return nil
	}

	svcCfg, ok := c.HTTP.Services[serviceName]
	if !ok {
		return nil
	}
	// Return a copy to prevent mutation
	result := make(map[string]any)
	maps.Copy(result, svcCfg)

	return result
}

// PublicScheme returns "http" or "https" from PublicOrigin.
// Returns "https" if PublicOrigin is empty or unparseable.
func (c *Config) PublicScheme() string {
	return PublicSchemeFromOrigin(c.PublicOrigin)
}

// PublicSchemeFromOrigin returns "http" or "https" derived from a public
// origin string. Returns "https" if the origin is empty or unparseable.
// Use this for callers that want a usable default scheme (config-aware
// callers and the token handler). Callers that must leave the scheme empty
// when the origin is empty or unparseable should use SchemeFromOrigin.
func PublicSchemeFromOrigin(publicOrigin string) string {
	if scheme := SchemeFromOrigin(publicOrigin); scheme != "" {
		return scheme
	}

	return schemeHTTPS
}

// SchemeFromOrigin returns the lowercased scheme ("http" or "https") derived
// from a public origin string, or an empty string when the origin is empty or
// unparseable. Unlike PublicSchemeFromOrigin it never substitutes a default
// scheme, preserving callers that intentionally treat an empty or unparseable
// origin as an empty scheme during hostport normalization.
func SchemeFromOrigin(publicOrigin string) string {
	if publicOrigin == "" {
		return ""
	}

	u, err := url.Parse(publicOrigin)
	if err != nil || u.Scheme == "" {
		return ""
	}

	return strings.ToLower(u.Scheme)
}
