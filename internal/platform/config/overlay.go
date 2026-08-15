// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"maps"
)

// ssrfFileConfig mirrors SSRFConfig for TOML decoding.
type ssrfFileConfig struct {
	Mode          string                           `toml:"mode"`
	RoutePolicy   string                           `toml:"route_policy"`
	RoutePolicies map[string]SSRFRoutePolicyConfig `toml:"route_policies"`
}

// outboundHTTPFileConfig mirrors OutboundHTTPConfig for TOML decoding, using
// *bool for use_env_fallback so an omitted key preserves the preset and an
// explicit true can opt in to ambient proxy discovery.
type outboundHTTPFileConfig struct {
	SSRF               *ssrfFileConfig `toml:"ssrf"`
	TimeoutMS          int             `toml:"timeout_ms"`
	ConnectTimeoutMS   int             `toml:"connect_timeout_ms"`
	MaxRedirects       int             `toml:"max_redirects"`
	MaxResponseBytes   int64           `toml:"max_response_bytes"`
	InsecureSkipVerify bool            `toml:"insecure_skip_verify"`
	TLSRootCAFile      string          `toml:"tls_root_ca_file"`
	TLSRootCADir       string          `toml:"tls_root_ca_dir"`
	ProxyURL           string          `toml:"proxy_url"`
	UseEnvFallback     *bool           `toml:"use_env_fallback"`
}

// persistenceFileConfig holds persistence settings from TOML.
type persistenceFileConfig struct {
	Backend    string `toml:"backend"`
	DataDir    string `toml:"data_dir"`
	ContentDir string `toml:"content_dir"`
}

// fileConfig mirrors Config but with pointer fields to detect presence.
type fileConfig struct {
	Mode   string        `toml:"mode"`
	Server *serverConfig `toml:"server"`

	PublicOrigin     string `toml:"public_origin"`
	ExternalBasePath string `toml:"external_base_path"`
	ListenAddr       string `toml:"listen_addr"`

	TLS           *TLSConfig              `toml:"tls"`
	OutboundHTTP  *outboundHTTPFileConfig `toml:"outbound_http"`
	Signature     *SignatureConfig        `toml:"signature"`
	Cache         *cacheConfig            `toml:"cache"`
	PeerTrust     *peerTrustConfig        `toml:"peer_trust"`
	Logging       *loggingConfig          `toml:"logging"`
	TokenExchange *tokenExchangeConfig    `toml:"token_exchange"`
	HTTP          *httpFileConfig         `toml:"http"`
	Persistence   *persistenceFileConfig  `toml:"persistence"`
	OCM           *ocmFileConfig          `toml:"ocm"`
	Statistics    *statisticsFileConfig   `toml:"statistics"`
}

// ocmFileConfig holds OCM settings from TOML.
type ocmFileConfig struct {
	CompatibilityScope string               `toml:"compatibility_scope"`
	Discovery          *discoveryFileConfig `toml:"discovery"`
	CodeFlow           *CodeFlowConfig      `toml:"code_flow"`
	PeerMapping        *PeerMappingConfig   `toml:"peer_compat"`
	Invite             *inviteFileConfig    `toml:"invite"`
}

// inviteFileConfig holds invite enforcement settings from TOML.
type inviteFileConfig struct {
	EnforceMustInvite *bool `toml:"enforce_must_invite"`
}

// discoveryFileConfig holds inbound peer discovery settings from TOML.
type discoveryFileConfig struct {
	PeerAPIVersionPolicy string `toml:"peer_api_version_policy"`
	PeerAPIVersionWarn   string `toml:"peer_api_version_warn"`
}

// httpFileConfig holds per-service HTTP configuration from TOML.
type httpFileConfig struct {
	Services     map[string]map[string]any `toml:"services"`
	Interceptors map[string]map[string]any `toml:"interceptors"`
}

// loggingConfig holds logging settings from TOML.
type loggingConfig struct {
	Level string `toml:"level"`
}

// tokenExchangeConfig holds token exchange settings from TOML.
type tokenExchangeConfig struct {
	Path string `toml:"path"`
}

// cacheConfig holds cache settings from TOML.
type cacheConfig struct {
	Driver  string         `toml:"driver"`
	Drivers map[string]any `toml:"drivers"`
}

// peerTrustConfig holds peer trust settings from TOML.
type peerTrustConfig struct {
	Enabled         bool                            `toml:"enabled"`
	ConfigPaths     []string                        `toml:"config_paths"`
	Policy          *peerTrustPolicyConfig          `toml:"policy"`
	MembershipCache *peerTrustMembershipCacheConfig `toml:"membership_cache"`
}

type peerTrustPolicyConfig struct {
	AllowList []string `toml:"allow_list"`
	DenyList  []string `toml:"deny_list"`
}

type peerTrustMembershipCacheConfig struct {
	TTLSeconds      int `toml:"ttl_seconds"`
	MaxStaleSeconds int `toml:"max_stale_seconds"`
}

// serverConfig holds server settings from TOML.
type serverConfig struct {
	TrustedProxies []string        `toml:"trusted_proxies"`
	BootstrapAdmin *bootstrapAdmin `toml:"bootstrap_admin"`
}

// bootstrapAdmin holds bootstrap admin credentials in TOML.
type bootstrapAdmin struct {
	Username       string `toml:"username"`
	Password       string `toml:"password"`
	CredentialFile string `toml:"password_file"`
}

type statisticsFileConfig struct {
	Enabled bool `toml:"enabled"`
}

func overlayStatisticsConfig(cfg *Config, fc *statisticsFileConfig) {
	if fc == nil {
		return
	}

	cfg.Statistics.Enabled = fc.Enabled
}

func overlayServerConfig(cfg *Config, fc *serverConfig) {
	if fc == nil {
		return
	}

	if len(fc.TrustedProxies) > 0 {
		cfg.Server.TrustedProxies = fc.TrustedProxies
	}

	if fc.BootstrapAdmin != nil {
		cfg.Server.BootstrapAdmin.Username = fc.BootstrapAdmin.Username
		cfg.Server.BootstrapAdmin.Password = fc.BootstrapAdmin.Password
		cfg.Server.BootstrapAdmin.CredentialFile = fc.BootstrapAdmin.CredentialFile
	}
}

func overlayTLSConfig(cfg *Config, fc *TLSConfig) {
	if fc == nil {
		return
	}

	if fc.Mode != "" {
		cfg.TLS.Mode = fc.Mode
	}

	if fc.CertFile != "" {
		cfg.TLS.CertFile = fc.CertFile
	}

	if fc.KeyFile != "" {
		cfg.TLS.KeyFile = fc.KeyFile
	}

	if fc.HTTPPort != 0 {
		cfg.TLS.HTTPPort = fc.HTTPPort
	}

	if fc.HTTPSPort != 0 {
		cfg.TLS.HTTPSPort = fc.HTTPSPort
	}

	if fc.SelfSignedDir != "" {
		cfg.TLS.SelfSignedDir = fc.SelfSignedDir
	}

	if fc.TLSDir != "" {
		cfg.TLS.TLSDir = fc.TLSDir
	}

	if fc.ACME.Email != "" {
		cfg.TLS.ACME.Email = fc.ACME.Email
	}

	if fc.ACME.Domain != "" {
		cfg.TLS.ACME.Domain = fc.ACME.Domain
	}

	if fc.ACME.Directory != "" {
		cfg.TLS.ACME.Directory = fc.ACME.Directory
	}

	if fc.ACME.StorageDir != "" {
		cfg.TLS.ACME.StorageDir = fc.ACME.StorageDir
	}
	// UseStaging is a bool, we overlay it if ACME section is present
	cfg.TLS.ACME.UseStaging = fc.ACME.UseStaging
}

func overlayOutboundHTTPSSRFConfig(cfg *Config, fc *ssrfFileConfig) {
	if fc == nil {
		return
	}

	if fc.Mode != "" {
		cfg.OutboundHTTP.SSRF.Mode = fc.Mode
	}

	if fc.RoutePolicy != "" {
		cfg.OutboundHTTP.SSRF.RoutePolicy = fc.RoutePolicy
	}

	if len(fc.RoutePolicies) > 0 {
		cfg.OutboundHTTP.SSRF.RoutePolicies = fc.RoutePolicies
	}
}

func overlayOutboundHTTPConfig(cfg *Config, fc *outboundHTTPFileConfig) {
	if fc == nil {
		return
	}

	overlayOutboundHTTPSSRFConfig(cfg, fc.SSRF)

	if fc.TimeoutMS != 0 {
		cfg.OutboundHTTP.TimeoutMS = fc.TimeoutMS
	}

	if fc.ConnectTimeoutMS != 0 {
		cfg.OutboundHTTP.ConnectTimeoutMS = fc.ConnectTimeoutMS
	}

	if fc.MaxRedirects != 0 {
		cfg.OutboundHTTP.MaxRedirects = fc.MaxRedirects
	}

	if fc.MaxResponseBytes != 0 {
		cfg.OutboundHTTP.MaxResponseBytes = fc.MaxResponseBytes
	}
	// InsecureSkipVerify is a bool, overlay always when section present
	cfg.OutboundHTTP.InsecureSkipVerify = fc.InsecureSkipVerify

	if fc.TLSRootCAFile != "" {
		cfg.OutboundHTTP.TLSRootCAFile = fc.TLSRootCAFile
	}

	if fc.TLSRootCADir != "" {
		cfg.OutboundHTTP.TLSRootCADir = fc.TLSRootCADir
	}

	if fc.ProxyURL != "" {
		cfg.OutboundHTTP.ProxyURL = fc.ProxyURL
	}

	if fc.UseEnvFallback != nil {
		cfg.OutboundHTTP.UseEnvFallback = *fc.UseEnvFallback
	}
}

func overlaySignatureConfig(cfg *Config, fc *SignatureConfig) {
	if fc == nil {
		return
	}

	if fc.KeyPath != "" {
		cfg.Signature.KeyPath = fc.KeyPath
	}

	if fc.Label != "" {
		cfg.Signature.Label = fc.Label
	}

	if fc.KidFragment != "" {
		cfg.Signature.KidFragment = fc.KidFragment
	}

	if fc.CreatedMaxAgeSeconds > 0 {
		cfg.Signature.CreatedMaxAgeSeconds = fc.CreatedMaxAgeSeconds
	}

	if fc.CreatedMaxSkewSeconds > 0 {
		cfg.Signature.CreatedMaxSkewSeconds = fc.CreatedMaxSkewSeconds
	}

	if len(fc.AllowedAlgorithms) > 0 {
		cfg.Signature.AllowedAlgorithms = fc.AllowedAlgorithms
	}

	if fc.JwksURI != "" {
		cfg.Signature.JwksURI = fc.JwksURI
	}
}

func overlayCacheConfig(cfg *Config, fc *cacheConfig) {
	if fc == nil {
		return
	}

	if fc.Driver != "" {
		cfg.Cache.Driver = fc.Driver
	}

	if len(fc.Drivers) > 0 {
		cfg.Cache.Drivers = fc.Drivers
	}
}

func overlayPeerTrustConfig(cfg *Config, fc *peerTrustConfig) {
	if fc == nil {
		return
	}

	cfg.PeerTrust.Enabled = fc.Enabled
	if len(fc.ConfigPaths) > 0 {
		cfg.PeerTrust.ConfigPaths = fc.ConfigPaths
	}

	if fc.Policy != nil {
		if len(fc.Policy.AllowList) > 0 {
			cfg.PeerTrust.Policy.AllowList = fc.Policy.AllowList
		}

		if len(fc.Policy.DenyList) > 0 {
			cfg.PeerTrust.Policy.DenyList = fc.Policy.DenyList
		}
	}

	if fc.MembershipCache != nil {
		if fc.MembershipCache.TTLSeconds > 0 {
			cfg.PeerTrust.MembershipCache.TTLSeconds = fc.MembershipCache.TTLSeconds
		}

		if fc.MembershipCache.MaxStaleSeconds > 0 {
			cfg.PeerTrust.MembershipCache.MaxStaleSeconds = fc.MembershipCache.MaxStaleSeconds
		}
	}
}

func overlayLoggingConfig(cfg *Config, fc *loggingConfig) {
	if fc == nil {
		return
	}

	if fc.Level != "" {
		cfg.Logging.Level = fc.Level
	}
}

func overlayTokenExchangeConfig(cfg *Config, fc *tokenExchangeConfig) {
	if fc == nil {
		return
	}

	if fc.Path != "" {
		cfg.TokenExchange.Path = fc.Path
	}
}

func overlayHTTPConfig(cfg *Config, fc *httpFileConfig) {
	if fc == nil {
		return
	}

	if len(fc.Services) > 0 {
		if cfg.HTTP.Services == nil {
			cfg.HTTP.Services = make(map[string]map[string]any)
		}

		maps.Copy(cfg.HTTP.Services, fc.Services)
	}

	if len(fc.Interceptors) > 0 {
		if cfg.HTTP.Interceptors == nil {
			cfg.HTTP.Interceptors = make(map[string]map[string]any)
		}

		maps.Copy(cfg.HTTP.Interceptors, fc.Interceptors)
	}
}

func overlayPersistenceConfig(cfg *Config, fc *persistenceFileConfig) {
	if fc == nil {
		return
	}

	if fc.Backend != "" {
		cfg.Persistence.Backend = fc.Backend
	}

	if fc.DataDir != "" {
		cfg.Persistence.DataDir = fc.DataDir
	}

	if fc.ContentDir != "" {
		cfg.Persistence.ContentDir = fc.ContentDir
	}
}

func overlayOCMCompatibilityScope(cfg *Config, scope string) {
	if scope == "" {
		return
	}

	parsed, err := ParseCompatibilityScope(scope)
	if err != nil {
		// Keep the raw value so validateEnums can report the invalid input.
		cfg.OCM.CompatibilityScope = CompatibilityScope(scope)
	} else {
		cfg.OCM.CompatibilityScope = parsed
	}
}

func overlayOCMDiscoveryConfig(cfg *Config, fc *discoveryFileConfig) {
	if fc == nil {
		return
	}

	if fc.PeerAPIVersionPolicy != "" {
		cfg.OCM.Discovery.PeerAPIVersionPolicy = fc.PeerAPIVersionPolicy
	}

	if fc.PeerAPIVersionWarn != "" {
		cfg.OCM.Discovery.PeerAPIVersionWarn = fc.PeerAPIVersionWarn
	}
}

func overlayOCMCodeFlowConfig(cfg *Config, fc *CodeFlowConfig) {
	if fc == nil {
		return
	}

	if fc.IncludesTokenExchangeRequirement != nil {
		cfg.OCM.CodeFlow.IncludesTokenExchangeRequirement = fc.IncludesTokenExchangeRequirement
	}

	if fc.RequiresTokenExchangeRequirement != nil {
		cfg.OCM.CodeFlow.RequiresTokenExchangeRequirement = fc.RequiresTokenExchangeRequirement
	}

	if fc.RequiresHTTPRequestSignatures != nil {
		cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures = fc.RequiresHTTPRequestSignatures
	}
}
