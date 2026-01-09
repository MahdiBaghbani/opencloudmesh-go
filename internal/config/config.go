// Package config provides configuration loading and validation.
package config

import (
	"fmt"
	"strings"
)

// Config holds the server configuration.
type Config struct {
	// Mode is the operating mode: strict, interop, or dev.
	Mode string `toml:"mode"`

	// ExternalOrigin is the public origin (scheme + host + port) for this instance.
	// Example: "https://localhost:9200"
	ExternalOrigin string `toml:"external_origin"`

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

	// PeerProfiles configuration for interop with different OCM implementations
	PeerProfiles PeerProfilesConfig `toml:"peer_profiles"`
}

// PeerProfilesConfig holds peer interop profile settings.
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

// PeerProfile defines interop behavior for a class of peers.
type PeerProfile struct {
	// AllowUnsignedInbound allows accepting unsigned requests
	AllowUnsignedInbound bool `toml:"allow_unsigned_inbound"`

	// AllowUnsignedOutbound allows sending unsigned requests
	AllowUnsignedOutbound bool `toml:"allow_unsigned_outbound"`

	// AllowMismatchedHost allows keyId host to differ from sender
	AllowMismatchedHost bool `toml:"allow_mismatched_host"`

	// AllowHTTP allows HTTP connections (dev-only)
	AllowHTTP bool `toml:"allow_http"`

	// TokenExchangeQuirks lists quirks to apply for token exchange
	TokenExchangeQuirks []string `toml:"token_exchange_quirks"`
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
	// Mode is one of: off, lenient, strict
	Mode string `toml:"mode"`

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

// OutboundHTTPConfig holds settings for outbound HTTP requests.
type OutboundHTTPConfig struct {
	// SSRFMode is one of: strict, off
	SSRFMode string `toml:"ssrf_mode"`

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
}


// OutboundHTTPConfigStrict returns strict outbound HTTP config for production.
func OutboundHTTPConfigStrict() OutboundHTTPConfig {
	return OutboundHTTPConfig{
		SSRFMode:           "strict",
		TimeoutMS:          10000,
		ConnectTimeoutMS:   2000,
		MaxRedirects:       1,
		MaxResponseBytes:   1048576,
		InsecureSkipVerify: false,
	}
}

// Redacted returns a string representation of the config with secrets redacted.
func (c *Config) Redacted() string {
	var sb strings.Builder
	sb.WriteString("Config{\n")
	sb.WriteString(fmt.Sprintf("  Mode: %q,\n", c.Mode))
	sb.WriteString(fmt.Sprintf("  ExternalOrigin: %q,\n", c.ExternalOrigin))
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
	sb.WriteString("  },\n")
	sb.WriteString("  OutboundHTTP: {\n")
	sb.WriteString(fmt.Sprintf("    SSRFMode: %q,\n", c.OutboundHTTP.SSRFMode))
	sb.WriteString(fmt.Sprintf("    TimeoutMS: %d,\n", c.OutboundHTTP.TimeoutMS))
	sb.WriteString(fmt.Sprintf("    MaxRedirects: %d,\n", c.OutboundHTTP.MaxRedirects))
	sb.WriteString(fmt.Sprintf("    MaxResponseBytes: %d,\n", c.OutboundHTTP.MaxResponseBytes))
	sb.WriteString(fmt.Sprintf("    InsecureSkipVerify: %v,\n", c.OutboundHTTP.InsecureSkipVerify))
	sb.WriteString("  },\n")
	sb.WriteString("  Signature: {\n")
	sb.WriteString(fmt.Sprintf("    Mode: %q,\n", c.Signature.Mode))
	sb.WriteString(fmt.Sprintf("    KeyPath: %q,\n", c.Signature.KeyPath))
	sb.WriteString(fmt.Sprintf("    OnDiscoveryError: %q,\n", c.Signature.OnDiscoveryError))
	sb.WriteString(fmt.Sprintf("    AllowMismatch: %v,\n", c.Signature.AllowMismatch))
	sb.WriteString("  },\n")
	sb.WriteString("  PeerProfiles: {\n")
	sb.WriteString(fmt.Sprintf("    MappingsCount: %d,\n", len(c.PeerProfiles.Mappings)))
	sb.WriteString(fmt.Sprintf("    CustomProfilesCount: %d,\n", len(c.PeerProfiles.CustomProfiles)))
	sb.WriteString("  },\n")
	sb.WriteString("}")
	return sb.String()
}
