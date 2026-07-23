package config

// ssrfFileConfig mirrors SSRFConfig for TOML decoding.
type ssrfFileConfig struct {
	Mode          string                           `toml:"mode"`
	RoutePolicy   string                           `toml:"route_policy"`
	RoutePolicies map[string]SSRFRoutePolicyConfig `toml:"route_policies"`
}

// outboundHTTPFileConfig mirrors OutboundHTTPConfig for TOML decoding, using
// *bool for proxy_env_fallback so an omitted key preserves the preset,
// an explicit false can opt out of a preset that defaults true (e.g. strict),
// and an explicit true can opt in from a preset that defaults false (e.g. dev).
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
	ProxyEnvFallback   *bool           `toml:"proxy_env_fallback"`
}

// persistenceFileConfig holds persistence settings from TOML.
type persistenceFileConfig struct {
	Backend string `toml:"backend"`
	DataDir string `toml:"data_dir"`
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
}

// ocmFileConfig holds OCM settings from TOML.
type ocmFileConfig struct {
	Discovery *discoveryFileConfig `toml:"discovery"`
	CodeFlow  *CodeFlowConfig      `toml:"code_flow"`
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
	Username string `toml:"username"`
	Password string `toml:"password"`
}

// overlayFileConfig applies TOML file values onto cfg.
func overlayFileConfig(cfg *Config, fc *fileConfig) {
	if fc.PublicOrigin != "" {
		cfg.PublicOrigin = fc.PublicOrigin
	}
	if fc.ExternalBasePath != "" {
		cfg.ExternalBasePath = fc.ExternalBasePath
	}
	if fc.ListenAddr != "" {
		cfg.ListenAddr = fc.ListenAddr
	}

	if fc.Server != nil {
		if len(fc.Server.TrustedProxies) > 0 {
			cfg.Server.TrustedProxies = fc.Server.TrustedProxies
		}
		if fc.Server.BootstrapAdmin != nil {
			cfg.Server.BootstrapAdmin.Username = fc.Server.BootstrapAdmin.Username
			cfg.Server.BootstrapAdmin.Password = fc.Server.BootstrapAdmin.Password
		}
	}

	if fc.TLS != nil {
		if fc.TLS.Mode != "" {
			cfg.TLS.Mode = fc.TLS.Mode
		}
		if fc.TLS.CertFile != "" {
			cfg.TLS.CertFile = fc.TLS.CertFile
		}
		if fc.TLS.KeyFile != "" {
			cfg.TLS.KeyFile = fc.TLS.KeyFile
		}
		if fc.TLS.HTTPPort != 0 {
			cfg.TLS.HTTPPort = fc.TLS.HTTPPort
		}
		if fc.TLS.HTTPSPort != 0 {
			cfg.TLS.HTTPSPort = fc.TLS.HTTPSPort
		}
		if fc.TLS.SelfSignedDir != "" {
			cfg.TLS.SelfSignedDir = fc.TLS.SelfSignedDir
		}
		if fc.TLS.TLSDir != "" {
			cfg.TLS.TLSDir = fc.TLS.TLSDir
		}
		if fc.TLS.ACME.Email != "" {
			cfg.TLS.ACME.Email = fc.TLS.ACME.Email
		}
		if fc.TLS.ACME.Domain != "" {
			cfg.TLS.ACME.Domain = fc.TLS.ACME.Domain
		}
		if fc.TLS.ACME.Directory != "" {
			cfg.TLS.ACME.Directory = fc.TLS.ACME.Directory
		}
		if fc.TLS.ACME.StorageDir != "" {
			cfg.TLS.ACME.StorageDir = fc.TLS.ACME.StorageDir
		}
		// UseStaging is a bool, we overlay it if ACME section is present
		cfg.TLS.ACME.UseStaging = fc.TLS.ACME.UseStaging
	}

	if fc.OutboundHTTP != nil {
		if fc.OutboundHTTP.SSRF != nil {
			if fc.OutboundHTTP.SSRF.Mode != "" {
				cfg.OutboundHTTP.SSRF.Mode = fc.OutboundHTTP.SSRF.Mode
			}
			if fc.OutboundHTTP.SSRF.RoutePolicy != "" {
				cfg.OutboundHTTP.SSRF.RoutePolicy = fc.OutboundHTTP.SSRF.RoutePolicy
			}
			if len(fc.OutboundHTTP.SSRF.RoutePolicies) > 0 {
				cfg.OutboundHTTP.SSRF.RoutePolicies = fc.OutboundHTTP.SSRF.RoutePolicies
			}
		}
		if fc.OutboundHTTP.TimeoutMS != 0 {
			cfg.OutboundHTTP.TimeoutMS = fc.OutboundHTTP.TimeoutMS
		}
		if fc.OutboundHTTP.ConnectTimeoutMS != 0 {
			cfg.OutboundHTTP.ConnectTimeoutMS = fc.OutboundHTTP.ConnectTimeoutMS
		}
		if fc.OutboundHTTP.MaxRedirects != 0 {
			cfg.OutboundHTTP.MaxRedirects = fc.OutboundHTTP.MaxRedirects
		}
		if fc.OutboundHTTP.MaxResponseBytes != 0 {
			cfg.OutboundHTTP.MaxResponseBytes = fc.OutboundHTTP.MaxResponseBytes
		}
		// InsecureSkipVerify is a bool, overlay always when section present
		cfg.OutboundHTTP.InsecureSkipVerify = fc.OutboundHTTP.InsecureSkipVerify
		if fc.OutboundHTTP.TLSRootCAFile != "" {
			cfg.OutboundHTTP.TLSRootCAFile = fc.OutboundHTTP.TLSRootCAFile
		}
		if fc.OutboundHTTP.TLSRootCADir != "" {
			cfg.OutboundHTTP.TLSRootCADir = fc.OutboundHTTP.TLSRootCADir
		}
		if fc.OutboundHTTP.ProxyURL != "" {
			cfg.OutboundHTTP.ProxyURL = fc.OutboundHTTP.ProxyURL
		}
		if fc.OutboundHTTP.ProxyEnvFallback != nil {
			cfg.OutboundHTTP.ProxyEnvFallback = *fc.OutboundHTTP.ProxyEnvFallback
		}
	}

	if fc.Signature != nil {
		if fc.Signature.KeyPath != "" {
			cfg.Signature.KeyPath = fc.Signature.KeyPath
		}
		if fc.Signature.Label != "" {
			cfg.Signature.Label = fc.Signature.Label
		}
		if fc.Signature.KidFragment != "" {
			cfg.Signature.KidFragment = fc.Signature.KidFragment
		}
		if fc.Signature.CreatedMaxAgeSeconds > 0 {
			cfg.Signature.CreatedMaxAgeSeconds = fc.Signature.CreatedMaxAgeSeconds
		}
		if fc.Signature.CreatedMaxSkewSeconds > 0 {
			cfg.Signature.CreatedMaxSkewSeconds = fc.Signature.CreatedMaxSkewSeconds
		}
		if len(fc.Signature.AllowedAlgorithms) > 0 {
			cfg.Signature.AllowedAlgorithms = fc.Signature.AllowedAlgorithms
		}
	}

	if fc.Cache != nil {
		if fc.Cache.Driver != "" {
			cfg.Cache.Driver = fc.Cache.Driver
		}
		if len(fc.Cache.Drivers) > 0 {
			cfg.Cache.Drivers = fc.Cache.Drivers
		}
	}

	if fc.PeerTrust != nil {
		cfg.PeerTrust.Enabled = fc.PeerTrust.Enabled
		if len(fc.PeerTrust.ConfigPaths) > 0 {
			cfg.PeerTrust.ConfigPaths = fc.PeerTrust.ConfigPaths
		}
		if fc.PeerTrust.Policy != nil {
			if len(fc.PeerTrust.Policy.AllowList) > 0 {
				cfg.PeerTrust.Policy.AllowList = fc.PeerTrust.Policy.AllowList
			}
			if len(fc.PeerTrust.Policy.DenyList) > 0 {
				cfg.PeerTrust.Policy.DenyList = fc.PeerTrust.Policy.DenyList
			}
		}
		if fc.PeerTrust.MembershipCache != nil {
			if fc.PeerTrust.MembershipCache.TTLSeconds > 0 {
				cfg.PeerTrust.MembershipCache.TTLSeconds = fc.PeerTrust.MembershipCache.TTLSeconds
			}
			if fc.PeerTrust.MembershipCache.MaxStaleSeconds > 0 {
				cfg.PeerTrust.MembershipCache.MaxStaleSeconds = fc.PeerTrust.MembershipCache.MaxStaleSeconds
			}
		}
	}

	if fc.Logging != nil {
		if fc.Logging.Level != "" {
			cfg.Logging.Level = fc.Logging.Level
		}
	}

	if fc.TokenExchange != nil {
		if fc.TokenExchange.Path != "" {
			cfg.TokenExchange.Path = fc.TokenExchange.Path
		}
	}

	if fc.HTTP != nil {
		if len(fc.HTTP.Services) > 0 {
			if cfg.HTTP.Services == nil {
				cfg.HTTP.Services = make(map[string]map[string]any)
			}
			for name, svcCfg := range fc.HTTP.Services {
				cfg.HTTP.Services[name] = svcCfg
			}
		}
		if len(fc.HTTP.Interceptors) > 0 {
			if cfg.HTTP.Interceptors == nil {
				cfg.HTTP.Interceptors = make(map[string]map[string]any)
			}
			for name, intCfg := range fc.HTTP.Interceptors {
				cfg.HTTP.Interceptors[name] = intCfg
			}
		}
	}

	if fc.Persistence != nil {
		if fc.Persistence.Backend != "" {
			cfg.Persistence.Backend = fc.Persistence.Backend
		}
		if fc.Persistence.DataDir != "" {
			cfg.Persistence.DataDir = fc.Persistence.DataDir
		}
	}

	if fc.OCM != nil && fc.OCM.Discovery != nil {
		if fc.OCM.Discovery.PeerAPIVersionPolicy != "" {
			cfg.OCM.Discovery.PeerAPIVersionPolicy = fc.OCM.Discovery.PeerAPIVersionPolicy
		}
		if fc.OCM.Discovery.PeerAPIVersionWarn != "" {
			cfg.OCM.Discovery.PeerAPIVersionWarn = fc.OCM.Discovery.PeerAPIVersionWarn
		}
	}

	if fc.OCM != nil && fc.OCM.CodeFlow != nil {
		if fc.OCM.CodeFlow.IncludesTokenExchangeRequirement != nil {
			cfg.OCM.CodeFlow.IncludesTokenExchangeRequirement = fc.OCM.CodeFlow.IncludesTokenExchangeRequirement
		}
		if fc.OCM.CodeFlow.RequiresTokenExchangeRequirement != nil {
			cfg.OCM.CodeFlow.RequiresTokenExchangeRequirement = fc.OCM.CodeFlow.RequiresTokenExchangeRequirement
		}
		if fc.OCM.CodeFlow.RequiresHTTPRequestSignatures != nil {
			cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures = fc.OCM.CodeFlow.RequiresHTTPRequestSignatures
		}
	}
}

// overlayFlags applies CLI flag values onto cfg.
func overlayFlags(cfg *Config, f FlagOverrides) {
	if f.ListenAddr != nil && *f.ListenAddr != "" {
		cfg.ListenAddr = *f.ListenAddr
	}
	if f.PublicOrigin != nil && *f.PublicOrigin != "" {
		cfg.PublicOrigin = *f.PublicOrigin
	}
	if f.ExternalBasePath != nil && *f.ExternalBasePath != "" {
		cfg.ExternalBasePath = *f.ExternalBasePath
	}
	if f.AdminUsername != nil && *f.AdminUsername != "" {
		cfg.Server.BootstrapAdmin.Username = *f.AdminUsername
	}
	if f.AdminPassword != nil && *f.AdminPassword != "" {
		cfg.Server.BootstrapAdmin.Password = *f.AdminPassword
	}
	if f.LoggingLevel != nil && *f.LoggingLevel != "" {
		cfg.Logging.Level = *f.LoggingLevel
	}
	if f.TokenExchangePath != nil && *f.TokenExchangePath != "" {
		cfg.TokenExchange.Path = *f.TokenExchangePath
	}
}
