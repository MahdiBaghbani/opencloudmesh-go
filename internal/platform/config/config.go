// Package config provides configuration loading and validation.
package config

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/instanceid"
)

// Config holds the server configuration.
type Config struct {
	// Mode selects a preset bundle: strict, compat, or dev.
	// The legacy alias "interop" is normalized to "compat" at load time.
	Mode string `toml:"mode"`

	// CompatibilityScope is the supervising exception-governance axis.
	// Values: "none", "scoped", "unbounded".
	CompatibilityScope string `toml:"compatibility_scope"`

	// PublicOrigin is the public origin (scheme + host + port) for this instance.
	// Example: "https://localhost:9200"
	PublicOrigin string `toml:"public_origin"`

	// ExternalBasePath is the optional path prefix for app endpoints.
	// Root-only endpoints (/.well-known/ocm, /ocm-provider) are never under this path.
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

	// PeerProfiles configuration for compatibility with different OCM implementations
	PeerProfiles PeerProfilesConfig `toml:"peer_profiles"`

	// Cache configuration
	Cache CacheConfig `toml:"cache"`

	// Peer trust configuration
	PeerTrust PeerTrustConfig `toml:"peer_trust"`

	// Logging configuration
	Logging LoggingConfig `toml:"logging"`

	// TokenExchange configuration
	TokenExchange TokenExchangeConfig `toml:"token_exchange"`

	// RequireTokenExchange controls whether local receive policy requires
	// must-exchange-token on WebDAV protocol requirements.
	RequireTokenExchange bool `toml:"require_token_exchange"`

	// PeerPolicy controls sender behavior toward non-strict peers.
	// Values: "legacy", "prefer-strict" (default), "strict".
	PeerPolicy string `toml:"peer_policy"`

	// HTTP holds per-service HTTP configuration (Reva-style).
	HTTP HTTPConfig `toml:"http"`
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
	// Default: info in strict/compat mode, debug in dev mode.
	Level string `toml:"level"`

	// AllowSensitive permits logging of sensitive values (tokens, secrets).
	// Default: false. Use only for debugging.
	AllowSensitive bool `toml:"allow_sensitive"`
}

// TokenExchangeConfig holds token exchange settings.
type TokenExchangeConfig struct {
	// Enabled controls whether token exchange is enabled.
	// Pointer for presence detection; nil = use preset default.
	// Default: preset-driven. Strict and dev enable it; compat inherits strict.
	Enabled *bool `toml:"enabled"`

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

	// ConfigPaths is a list of paths to K2 JSON trust group config files.
	// Required when enabled.
	ConfigPaths []string `toml:"config_paths"`

	// Policy contains trust policy settings.
	Policy PeerTrustPolicyConfig `toml:"policy"`

	// MembershipCache contains membership cache settings.
	MembershipCache PeerTrustMembershipCacheConfig `toml:"membership_cache"`
}

// PeerTrustPolicyConfig holds peer trust policy settings.
type PeerTrustPolicyConfig struct {
	// GlobalEnforce enforces membership checks globally.
	GlobalEnforce bool `toml:"global_enforce"`

	// AllowList is a list of always-allowed hosts.
	AllowList []string `toml:"allow_list"`

	// DenyList is a list of always-denied hosts.
	DenyList []string `toml:"deny_list"`

	// ExemptList is a list of hosts exempt from membership checks.
	ExemptList []string `toml:"exempt_list"`
}

// PeerTrustMembershipCacheConfig holds membership cache settings.
type PeerTrustMembershipCacheConfig struct {
	// TTLSeconds is the cache TTL in seconds. Default: 21600 (6 hours).
	TTLSeconds int `toml:"ttl_seconds"`

	// MaxStaleSeconds is the max staleness before treating as unavailable. Default: 604800 (7 days).
	MaxStaleSeconds int `toml:"max_stale_seconds"`
}

// PeerProfilesConfig holds peer compatibility profile settings.
type PeerProfilesConfig struct {
	// Mappings maps domain patterns to profile names
	// Example: [{ pattern = "*.nextcloud.com", profile = "nextcloud" }]
	Mappings []PeerProfileMapping `toml:"mappings"`

	// CustomProfiles defines custom profile overrides
	CustomProfiles map[string]PeerProfile `toml:"custom_profiles"`
}

// PeerProfileMapping maps a domain pattern to a profile name.
type PeerProfileMapping struct {
	// Pattern is a domain pattern (exact or glob like "*.example.com")
	Pattern string `toml:"pattern"`

	// Profile is the name of the profile to use
	Profile string `toml:"profile"`
}

// PeerProfile defines compatibility behavior for a class of peers.
type PeerProfile struct {
	// AllowUnsignedInbound allows accepting unsigned requests
	AllowUnsignedInbound bool `toml:"allow_unsigned_inbound"`

	// AllowUnsignedOutbound allows sending unsigned requests
	AllowUnsignedOutbound bool `toml:"allow_unsigned_outbound"`

	// AllowMismatchedHost allows keyId host to differ from sender
	AllowMismatchedHost bool `toml:"allow_mismatched_host"`

	// AllowHTTP allows HTTP connections (dev-only)
	AllowHTTP bool `toml:"allow_http"`

	// AllowUnsignedDiscovery allows discovery-based signature capability checks
	// to fail open for this peer in the narrow retained call sites.
	AllowUnsignedDiscovery bool `toml:"allow_unsigned_discovery"`

	// AcceptLegacyDiscoveryPublicKey allows this peer to fall back from legacy
	// discovery publicKey into canonical publicKeys during normalization.
	AcceptLegacyDiscoveryPublicKey bool `toml:"accept_legacy_discovery_public_key"`

	// TokenExchangeQuirks lists quirks to apply for token exchange
	TokenExchangeQuirks []string `toml:"token_exchange_quirks"`

	// TokenExchangeGrantType overrides the outbound token exchange grant_type.
	// Empty means the protocol default ("authorization_code").
	TokenExchangeGrantType string `toml:"token_exchange_grant_type"`

	// AllowedBasicAuthPatterns whitelists specific Basic auth patterns.
	// Empty means allow all implemented patterns.
	AllowedBasicAuthPatterns []string `toml:"allowed_basic_auth_patterns"`
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
}

// SignatureConfig holds HTTP signature settings.
type SignatureConfig struct {
	// InboundMode controls inbound signature enforcement: strict, lenient, off
	InboundMode string `toml:"inbound_mode"`

	// OutboundMode controls outbound signing: strict, criteria-only, token-only, off
	OutboundMode string `toml:"outbound_mode"`

	// PeerProfileLevelOverride controls when peer profile relaxations apply:
	// all, non-strict, off (strict preset default: off)
	PeerProfileLevelOverride string `toml:"peer_profile_level_override"`

	// KeyPath is where the signing private key is stored
	KeyPath string `toml:"key_path"`

	// OnDiscoveryError determines behavior when peer discovery fails:
	// "reject" (default) or "allow" (dev-only)
	OnDiscoveryError string `toml:"on_discovery_error"`

	// AllowMismatch allows declared peer vs keyId host mismatch (dev-only)
	AllowMismatch bool `toml:"allow_mismatch"`
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
	// Catch-all CIDRs (0.0.0.0/0, ::/0) are rejected under none/scoped scopes.
	AllowPrivateCIDRs []string `toml:"allow_private_cidrs"`

	// AllowedPorts restricts which destination ports are permitted.
	AllowedPorts []int `toml:"allowed_ports"`

	// AllowIPLiterals permits direct IP address targets when true.
	// Must be false under compatibility_scope=none and scoped.
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

	// SSRFMode is a derived shim populated from SSRF.Mode by the config loader.
	// It is not decoded from TOML; use [outbound_http.ssrf] instead.
	// Retained for runtime client compatibility until T2 migrates the client.
	SSRFMode string `toml:"-"`

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
	// When set under compatibility_scope=none the proxy host is
	// operator-trusted; private and loopback addresses are permitted.
	// When set, proxy_url takes precedence over proxy_env_fallback; the
	// explicit URL is used and environment variables are not consulted.
	ProxyURL string `toml:"proxy_url"`

	// ProxyEnvFallback enables reading HTTP_PROXY/HTTPS_PROXY/NO_PROXY from
	// the environment when proxy_url is not set.
	// Default: true for strict and compat presets, false for dev preset.
	// Set to false to disable environment-based proxy discovery entirely.
	ProxyEnvFallback bool `toml:"proxy_env_fallback"`
}

// OutboundHTTPConfigStrict returns strict outbound HTTP config for production.
func OutboundHTTPConfigStrict() OutboundHTTPConfig {
	return OutboundHTTPConfig{
		SSRF:               SSRFConfig{Mode: "strict"},
		SSRFMode:           "strict",
		TimeoutMS:          10000,
		ConnectTimeoutMS:   2000,
		MaxRedirects:       1,
		MaxResponseBytes:   1048576,
		InsecureSkipVerify: false,
	}
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
	for k, v := range svcCfg {
		result[k] = v
	}
	return result
}

// TokenExchangeEnabled returns whether token exchange is enabled.
// Safe for nil pointer on the *bool field.
func (c *Config) TokenExchangeEnabled() bool {
	return c.TokenExchange.Enabled != nil && *c.TokenExchange.Enabled
}

// Redacted returns a string representation of the config with secrets redacted.
func (c *Config) Redacted() string {
	var sb strings.Builder
	sb.WriteString("Config{\n")
	sb.WriteString(fmt.Sprintf("  Mode: %q,\n", c.Mode))
	sb.WriteString(fmt.Sprintf("  CompatibilityScope: %q,\n", c.CompatibilityScope))
	sb.WriteString(fmt.Sprintf("  PublicOrigin: %q,\n", c.PublicOrigin))
	sb.WriteString(fmt.Sprintf("  ExternalBasePath: %q,\n", c.ExternalBasePath))
	sb.WriteString(fmt.Sprintf("  ListenAddr: %q,\n", c.ListenAddr))
	sb.WriteString("  Server: {\n")
	sb.WriteString(fmt.Sprintf("    TrustedProxies: %v,\n", c.Server.TrustedProxies))
	sb.WriteString("    BootstrapAdmin: {\n")
	sb.WriteString(fmt.Sprintf("      Username: %q,\n", c.Server.BootstrapAdmin.Username))
	sb.WriteString("      Password: [REDACTED],\n")
	sb.WriteString("    },\n")
	sb.WriteString("  },\n")
	sb.WriteString("  TLS: {\n")
	sb.WriteString(fmt.Sprintf("    Mode: %q,\n", c.TLS.Mode))
	sb.WriteString(fmt.Sprintf("    CertFile: %q,\n", c.TLS.CertFile))
	sb.WriteString(fmt.Sprintf("    KeyFile: %q,\n", c.TLS.KeyFile))
	sb.WriteString(fmt.Sprintf("    HTTPPort: %d,\n", c.TLS.HTTPPort))
	sb.WriteString(fmt.Sprintf("    HTTPSPort: %d,\n", c.TLS.HTTPSPort))
	sb.WriteString(fmt.Sprintf("    SelfSignedDir: %q,\n", c.TLS.SelfSignedDir))
	sb.WriteString(fmt.Sprintf("    TLSDir: %q,\n", c.TLS.TLSDir))
	sb.WriteString("  },\n")
	sb.WriteString("  OutboundHTTP: {\n")
	sb.WriteString("    SSRF: {\n")
	sb.WriteString(fmt.Sprintf("      Mode: %q,\n", c.OutboundHTTP.SSRF.Mode))
	if c.OutboundHTTP.SSRF.RoutePolicy != "" {
		sb.WriteString(fmt.Sprintf("      RoutePolicy: %q,\n", c.OutboundHTTP.SSRF.RoutePolicy))
	}
	sb.WriteString(fmt.Sprintf("      RoutePoliciesCount: %d,\n", len(c.OutboundHTTP.SSRF.RoutePolicies)))
	sb.WriteString("    },\n")
	sb.WriteString(fmt.Sprintf("    TLSRootCAFile: %q,\n", c.OutboundHTTP.TLSRootCAFile))
	sb.WriteString(fmt.Sprintf("    TLSRootCADir: %q,\n", c.OutboundHTTP.TLSRootCADir))
	sb.WriteString(fmt.Sprintf("    TimeoutMS: %d,\n", c.OutboundHTTP.TimeoutMS))
	sb.WriteString(fmt.Sprintf("    MaxRedirects: %d,\n", c.OutboundHTTP.MaxRedirects))
	sb.WriteString(fmt.Sprintf("    MaxResponseBytes: %d,\n", c.OutboundHTTP.MaxResponseBytes))
	sb.WriteString(fmt.Sprintf("    InsecureSkipVerify: %v,\n", c.OutboundHTTP.InsecureSkipVerify))
	sb.WriteString(fmt.Sprintf("    ProxyURL: %q,\n", c.OutboundHTTP.ProxyURL))
	sb.WriteString(fmt.Sprintf("    ProxyEnvFallback: %v,\n", c.OutboundHTTP.ProxyEnvFallback))
	sb.WriteString("  },\n")
	sb.WriteString("  Signature: {\n")
	sb.WriteString(fmt.Sprintf("    InboundMode: %q,\n", c.Signature.InboundMode))
	sb.WriteString(fmt.Sprintf("    OutboundMode: %q,\n", c.Signature.OutboundMode))
	sb.WriteString(fmt.Sprintf("    PeerProfileLevelOverride: %q,\n", c.Signature.PeerProfileLevelOverride))
	sb.WriteString(fmt.Sprintf("    KeyPath: %q,\n", c.Signature.KeyPath))
	sb.WriteString(fmt.Sprintf("    OnDiscoveryError: %q,\n", c.Signature.OnDiscoveryError))
	sb.WriteString(fmt.Sprintf("    AllowMismatch: %v,\n", c.Signature.AllowMismatch))
	sb.WriteString("  },\n")
	sb.WriteString("  PeerProfiles: {\n")
	sb.WriteString(fmt.Sprintf("    MappingsCount: %d,\n", len(c.PeerProfiles.Mappings)))
	sb.WriteString(fmt.Sprintf("    CustomProfilesCount: %d,\n", len(c.PeerProfiles.CustomProfiles)))
	sb.WriteString("  },\n")
	sb.WriteString("  Logging: {\n")
	sb.WriteString(fmt.Sprintf("    Level: %q,\n", c.Logging.Level))
	sb.WriteString(fmt.Sprintf("    AllowSensitive: %v,\n", c.Logging.AllowSensitive))
	sb.WriteString("  },\n")
	sb.WriteString("  TokenExchange: {\n")
	enabledStr := "<nil>"
	if c.TokenExchange.Enabled != nil {
		enabledStr = fmt.Sprintf("%v", *c.TokenExchange.Enabled)
	}
	sb.WriteString(fmt.Sprintf("    Enabled: %s,\n", enabledStr))
	sb.WriteString(fmt.Sprintf("    Path: %q,\n", c.TokenExchange.Path))
	sb.WriteString("  },\n")
	sb.WriteString(fmt.Sprintf("  RequireTokenExchange: %v,\n", c.RequireTokenExchange))
	sb.WriteString(fmt.Sprintf("  PeerPolicy: %q,\n", c.PeerPolicy))
	sb.WriteString("  HTTP: {\n")
	sb.WriteString(fmt.Sprintf("    ServicesCount: %d,\n", len(c.HTTP.Services)))
	if len(c.HTTP.Services) > 0 {
		sb.WriteString("    Services: [")
		first := true
		for name := range c.HTTP.Services {
			if !first {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("%q", name))
			first = false
		}
		sb.WriteString("],\n")
	}
	sb.WriteString("  },\n")
	sb.WriteString("  PeerTrust: {\n")
	sb.WriteString(fmt.Sprintf("    Enabled: %v,\n", c.PeerTrust.Enabled))
	sb.WriteString(fmt.Sprintf("    ConfigPathsCount: %d,\n", len(c.PeerTrust.ConfigPaths)))
	sb.WriteString(fmt.Sprintf("    Policy.GlobalEnforce: %v,\n", c.PeerTrust.Policy.GlobalEnforce))
	sb.WriteString(fmt.Sprintf("    Policy.AllowListCount: %d,\n", len(c.PeerTrust.Policy.AllowList)))
	sb.WriteString(fmt.Sprintf("    Policy.DenyListCount: %d,\n", len(c.PeerTrust.Policy.DenyList)))
	sb.WriteString(fmt.Sprintf("    Policy.ExemptListCount: %d,\n", len(c.PeerTrust.Policy.ExemptList)))
	sb.WriteString(fmt.Sprintf("    MembershipCache.TTLSeconds: %d,\n", c.PeerTrust.MembershipCache.TTLSeconds))
	sb.WriteString(fmt.Sprintf("    MembershipCache.MaxStaleSeconds: %d,\n", c.PeerTrust.MembershipCache.MaxStaleSeconds))
	sb.WriteString("  },\n")
	sb.WriteString("}")
	return sb.String()
}

// PublicScheme returns "http" or "https" from PublicOrigin.
// Returns "https" if PublicOrigin is empty or unparseable.
func (c *Config) PublicScheme() string {
	if c.PublicOrigin == "" {
		return "https"
	}
	u, err := url.Parse(c.PublicOrigin)
	if err != nil || u.Scheme == "" {
		return "https"
	}
	return strings.ToLower(u.Scheme)
}

// PublicAuthority returns the lowercased host[:port] from PublicOrigin.
func (c *Config) PublicAuthority() string {
	fqdn, err := instanceid.ProviderFQDN(c.PublicOrigin)
	if err != nil {
		return ""
	}
	return fqdn
}
