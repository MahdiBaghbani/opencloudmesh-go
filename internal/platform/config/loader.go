// Package config provides configuration loading and validation.
package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Mode represents the server operating mode.
type Mode string

const (
	ModeStrict  Mode = "strict"
	ModeInterop Mode = "interop"
	ModeDev     Mode = "dev"
)

// ParseMode parses a mode string, returning an error for invalid values.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict", "":
		return ModeStrict, nil
	case "interop":
		return ModeInterop, nil
	case "dev":
		return ModeDev, nil
	default:
		return "", fmt.Errorf("invalid mode %q: must be one of strict, interop, dev", s)
	}
}

// LoaderOptions controls how configuration is loaded.
type LoaderOptions struct {
	// ConfigPath is the path to a TOML config file (optional).
	// If provided but file is missing or invalid, loading fails.
	ConfigPath string

	// ModeFlag is the --mode flag value (overrides config file mode).
	ModeFlag string

	// FlagOverrides are CLI flag values that override config file values.
	FlagOverrides FlagOverrides

	// Logger is used for warning messages (e.g., undecoded keys).
	// If nil, slog.Default() is used.
	Logger *slog.Logger
}

// FlagOverrides holds CLI flag values that override config file values.
type FlagOverrides struct {
	ListenAddr                     *string
	PublicOrigin                   *string
	ExternalBasePath               *string
	SSRFMode                       *string
	SignatureInboundMode           *string
	SignatureOutboundMode          *string
	SignatureAdvertiseHTTPReqSigs  *string // "true", "false", or "" (unset)
	SignaturePeerProfileOverride   *string
	TLSMode                        *string
	AdminUsername                  *string
	AdminPassword                  *string
	LoggingLevel                   *string
	LoggingAllowSensitive          *string // "true", "false", or "" (unset)
	TokenExchangeEnabled           *string // "true", "false", or "" (unset)
	TokenExchangePath              *string
	WebDAVTokenExchangeMode        *string
}

// fileConfig mirrors Config but with pointer fields to detect presence.
type fileConfig struct {
	Mode   string        `toml:"mode"`
	Server *serverConfig `toml:"server"`

	PublicOrigin     string `toml:"public_origin"`
	ExternalBasePath string `toml:"external_base_path"`
	ListenAddr       string `toml:"listen_addr"`

	TLS          *TLSConfig          `toml:"tls"`
	OutboundHTTP *OutboundHTTPConfig `toml:"outbound_http"`
	Signature    *SignatureConfig    `toml:"signature"`
	PeerProfiles *peerProfilesConfig `toml:"peer_profiles"`
	Cache               *cacheConfig               `toml:"cache"`
	PeerTrust           *peerTrustConfig           `toml:"peer_trust"`
	Logging             *loggingConfig             `toml:"logging"`
	TokenExchange       *tokenExchangeConfig       `toml:"token_exchange"`
	WebDAVTokenExchange *webdavTokenExchangeConfig `toml:"webdav_token_exchange"`
	HTTP                *httpFileConfig            `toml:"http"`
}

// httpFileConfig holds per-service HTTP configuration from TOML.
type httpFileConfig struct {
	Services     map[string]map[string]any `toml:"services"`
	Interceptors map[string]map[string]any `toml:"interceptors"`
}

// loggingConfig holds logging settings from TOML.
type loggingConfig struct {
	Level          string `toml:"level"`
	AllowSensitive bool   `toml:"allow_sensitive"`
}

// tokenExchangeConfig holds token exchange settings from TOML.
type tokenExchangeConfig struct {
	Enabled *bool  `toml:"enabled"`
	Path    string `toml:"path"`
}

// webdavTokenExchangeConfig holds WebDAV token exchange enforcement settings from TOML.
type webdavTokenExchangeConfig struct {
	Mode string `toml:"mode"`
}

// cacheConfig holds cache settings from TOML.
type cacheConfig struct {
	Driver  string         `toml:"driver"`
	Drivers map[string]any `toml:"drivers"`
}

// peerTrustConfig holds peer trust settings from TOML.
type peerTrustConfig struct {
	Enabled         bool                              `toml:"enabled"`
	ConfigPaths     []string                          `toml:"config_paths"`
	Policy          *peerTrustPolicyConfig            `toml:"policy"`
	MembershipCache *peerTrustMembershipCacheConfig   `toml:"membership_cache"`
}

type peerTrustPolicyConfig struct {
	GlobalEnforce bool     `toml:"global_enforce"`
	AllowList     []string `toml:"allow_list"`
	DenyList      []string `toml:"deny_list"`
	ExemptList    []string `toml:"exempt_list"`
}

type peerTrustMembershipCacheConfig struct {
	TTLSeconds      int `toml:"ttl_seconds"`
	MaxStaleSeconds int `toml:"max_stale_seconds"`
}

// peerProfilesConfig holds peer profile settings from TOML.
type peerProfilesConfig struct {
	Mappings       []PeerProfileMapping       `toml:"mappings"`
	CustomProfiles map[string]PeerProfile     `toml:"custom_profiles"`
}

// serverConfig holds server-specific settings in TOML.
type serverConfig struct {
	TrustedProxies []string        `toml:"trusted_proxies"`
	BootstrapAdmin *bootstrapAdmin `toml:"bootstrap_admin"`
}

// bootstrapAdmin holds bootstrap admin credentials in TOML.
type bootstrapAdmin struct {
	Username string `toml:"username"`
	Password string `toml:"password"`
}

// Load loads configuration with the following precedence:
//  1. Determine effective mode: --mode flag > mode in config file > default (strict)
//  2. Start from mode preset defaults
//  3. Overlay TOML config file values
//  4. Overlay CLI flags
//  5. Validate enum fields
//
// If ConfigPath is provided but the file is missing, unreadable, or invalid TOML,
// Load returns an error (fail fast). Unknown/undecoded TOML keys produce a warning
// but do not fail the load.
func Load(opts LoaderOptions) (*Config, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	var fc fileConfig

	// Step 1: Load TOML file if provided
	if opts.ConfigPath != "" {
		data, err := os.ReadFile(opts.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", opts.ConfigPath, err)
		}
		md, err := toml.Decode(string(data), &fc)
		if err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", opts.ConfigPath, err)
		}

		// Strict breaks: reject renamed keys with clear migration messages.
		if undecoded := md.Undecoded(); len(undecoded) > 0 {
			keys := make([]string, 0, len(undecoded))
			for _, k := range undecoded {
				keyStr := k.String()
				if keyStr == "external_origin" {
					return nil, fmt.Errorf("config key 'external_origin' has been renamed to 'public_origin'; please update your configuration")
				}
				if keyStr == "federation" || strings.HasPrefix(keyStr, "federation.") {
					return nil, fmt.Errorf("config section '[federation]' has been renamed to '[peer_trust]'; please update your configuration")
				}
				keys = append(keys, keyStr)
			}
			// Warn about remaining undecoded keys (do not fail)
			if len(keys) > 0 {
				logger.Warn("config file contains undecoded keys", "path", opts.ConfigPath, "keys", keys)
			}
		}
	}

	// Step 2: Determine effective mode
	modeStr := "strict" // default
	if fc.Mode != "" {
		modeStr = fc.Mode
	}
	if opts.ModeFlag != "" {
		modeStr = opts.ModeFlag
	}

	mode, err := ParseMode(modeStr)
	if err != nil {
		return nil, err
	}

	// Step 3: Start from mode preset
	cfg := presetForMode(mode)

	// Step 4: Overlay TOML values
	if opts.ConfigPath != "" {
		overlayFileConfig(cfg, &fc)
	}

	// Step 5: Overlay CLI flags
	overlayFlags(cfg, opts.FlagOverrides)

	// Step 6: Validate enum fields (fatal on invalid values)
	if err := validateEnums(cfg); err != nil {
		return nil, err
	}

	// Step 7: Validate public_origin format (fail fast on invalid URL)
	if err := validatePublicOrigin(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ptrBool returns a pointer to the given bool value.
func ptrBool(b bool) *bool { return &b }

// presetForMode returns the base config for a given mode.
func presetForMode(mode Mode) *Config {
	switch mode {
	case ModeDev:
		return DevConfig()
	case ModeInterop:
		return InteropConfig()
	default:
		return StrictConfig()
	}
}

// StrictConfig returns production-safe strict defaults.
func StrictConfig() *Config {
	return &Config{
		Mode:             string(ModeStrict),
		PublicOrigin:     "https://localhost:9200",
		ExternalBasePath: "",
		ListenAddr:       ":9200",
		Server: ServerConfig{
			TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		},
		TLS: TLSConfig{
			Mode:          "selfsigned",
			HTTPPort:      9280,
			HTTPSPort:     9200,
			SelfSignedDir: ".ocm/certs",
			ACME: ACMEConfig{
				Directory:  "https://acme-v02.api.letsencrypt.org/directory",
				StorageDir: ".ocm/acme",
				UseStaging: false,
			},
		},
		OutboundHTTP: OutboundHTTPConfig{
			SSRFMode:           "strict",
			TimeoutMS:          10000,
			ConnectTimeoutMS:   2000,
			MaxRedirects:       1,
			MaxResponseBytes:   1048576,
			InsecureSkipVerify: false,
		},
		Signature: SignatureConfig{
			InboundMode:                    "strict",
			OutboundMode:                   "strict",
			AdvertiseHTTPRequestSignatures: true,
			PeerProfileLevelOverride:       "non-strict",
			KeyPath:                        ".ocm/keys/signing.pem",
			OnDiscoveryError:               "reject",
			AllowMismatch:                  false,
		},
		PeerTrust: PeerTrustConfig{
			Enabled:     false,
			ConfigPaths: nil,
			MembershipCache: PeerTrustMembershipCacheConfig{
				TTLSeconds:      21600,  // 6 hours
				MaxStaleSeconds: 604800, // 7 days
			},
		},
		Logging: LoggingConfig{
			Level:          "info",
			AllowSensitive: false,
		},
		TokenExchange: TokenExchangeConfig{
			Enabled: ptrBool(true),
			Path:    "token",
		},
		WebDAVTokenExchange: WebDAVTokenExchangeConfig{
			Mode: "strict",
		},
	}
}

// InteropConfig returns interop mode defaults.
func InteropConfig() *Config {
	cfg := StrictConfig()
	cfg.Mode = string(ModeInterop)
	cfg.Signature.InboundMode = "lenient"
	cfg.Signature.OutboundMode = "criteria-only"
	cfg.Signature.AdvertiseHTTPRequestSignatures = true
	cfg.Signature.PeerProfileLevelOverride = "non-strict"
	cfg.WebDAVTokenExchange.Mode = "lenient"
	// InsecureSkipVerify stays configurable (default false)
	return cfg
}

// DevConfig returns development mode defaults.
func DevConfig() *Config {
	return &Config{
		Mode:             string(ModeDev),
		PublicOrigin:     "https://localhost:9200",
		ExternalBasePath: "",
		ListenAddr:       ":9200",
		Server: ServerConfig{
			TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		},
		TLS: TLSConfig{
			Mode:          "off",
			HTTPPort:      9280,
			HTTPSPort:     9200,
			SelfSignedDir: ".ocm/certs",
			ACME: ACMEConfig{
				Directory:  "https://acme-staging-v02.api.letsencrypt.org/directory",
				StorageDir: ".ocm/acme",
				UseStaging: true,
			},
		},
		OutboundHTTP: OutboundHTTPConfig{
			SSRFMode:           "off",
			TimeoutMS:          10000,
			ConnectTimeoutMS:   2000,
			MaxRedirects:       3,
			MaxResponseBytes:   1048576,
			InsecureSkipVerify: true,
		},
		Signature: SignatureConfig{
			InboundMode:                    "lenient",
			OutboundMode:                   "criteria-only",
			AdvertiseHTTPRequestSignatures: true,
			PeerProfileLevelOverride:       "non-strict",
			KeyPath:                        ".ocm/keys/signing.pem",
			OnDiscoveryError:               "allow",
			AllowMismatch:                  true,
		},
		PeerTrust: PeerTrustConfig{
			Enabled:     false,
			ConfigPaths: nil,
			MembershipCache: PeerTrustMembershipCacheConfig{
				TTLSeconds:      21600,  // 6 hours
				MaxStaleSeconds: 604800, // 7 days
			},
		},
		Logging: LoggingConfig{
			Level:          "debug",
			AllowSensitive: false,
		},
		TokenExchange: TokenExchangeConfig{
			Enabled: ptrBool(true),
			Path:    "token",
		},
		WebDAVTokenExchange: WebDAVTokenExchangeConfig{
			Mode: "lenient",
		},
	}
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
		if fc.OutboundHTTP.SSRFMode != "" {
			cfg.OutboundHTTP.SSRFMode = fc.OutboundHTTP.SSRFMode
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
	}

	if fc.Signature != nil {
		if fc.Signature.InboundMode != "" {
			cfg.Signature.InboundMode = fc.Signature.InboundMode
		}
		if fc.Signature.OutboundMode != "" {
			cfg.Signature.OutboundMode = fc.Signature.OutboundMode
		}
		// AdvertiseHTTPRequestSignatures is bool, overlay when section present
		cfg.Signature.AdvertiseHTTPRequestSignatures = fc.Signature.AdvertiseHTTPRequestSignatures
		if fc.Signature.PeerProfileLevelOverride != "" {
			cfg.Signature.PeerProfileLevelOverride = fc.Signature.PeerProfileLevelOverride
		}
		if fc.Signature.KeyPath != "" {
			cfg.Signature.KeyPath = fc.Signature.KeyPath
		}
		if fc.Signature.OnDiscoveryError != "" {
			cfg.Signature.OnDiscoveryError = fc.Signature.OnDiscoveryError
		}
		// AllowMismatch is bool
		cfg.Signature.AllowMismatch = fc.Signature.AllowMismatch
	}

	if fc.PeerProfiles != nil {
		if len(fc.PeerProfiles.Mappings) > 0 {
			cfg.PeerProfiles.Mappings = fc.PeerProfiles.Mappings
		}
		if len(fc.PeerProfiles.CustomProfiles) > 0 {
			cfg.PeerProfiles.CustomProfiles = fc.PeerProfiles.CustomProfiles
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
			cfg.PeerTrust.Policy.GlobalEnforce = fc.PeerTrust.Policy.GlobalEnforce
			if len(fc.PeerTrust.Policy.AllowList) > 0 {
				cfg.PeerTrust.Policy.AllowList = fc.PeerTrust.Policy.AllowList
			}
			if len(fc.PeerTrust.Policy.DenyList) > 0 {
				cfg.PeerTrust.Policy.DenyList = fc.PeerTrust.Policy.DenyList
			}
			if len(fc.PeerTrust.Policy.ExemptList) > 0 {
				cfg.PeerTrust.Policy.ExemptList = fc.PeerTrust.Policy.ExemptList
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
		// AllowSensitive is a bool, overlay when section present
		cfg.Logging.AllowSensitive = fc.Logging.AllowSensitive
	}

	if fc.TokenExchange != nil {
		if fc.TokenExchange.Enabled != nil {
			cfg.TokenExchange.Enabled = fc.TokenExchange.Enabled
		}
		if fc.TokenExchange.Path != "" {
			cfg.TokenExchange.Path = fc.TokenExchange.Path
		}
	}

	if fc.WebDAVTokenExchange != nil {
		if fc.WebDAVTokenExchange.Mode != "" {
			cfg.WebDAVTokenExchange.Mode = fc.WebDAVTokenExchange.Mode
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
	if f.SSRFMode != nil && *f.SSRFMode != "" {
		cfg.OutboundHTTP.SSRFMode = *f.SSRFMode
	}
	if f.SignatureInboundMode != nil && *f.SignatureInboundMode != "" {
		cfg.Signature.InboundMode = *f.SignatureInboundMode
	}
	if f.SignatureOutboundMode != nil && *f.SignatureOutboundMode != "" {
		cfg.Signature.OutboundMode = *f.SignatureOutboundMode
	}
	if f.SignatureAdvertiseHTTPReqSigs != nil && *f.SignatureAdvertiseHTTPReqSigs != "" {
		// Parse "true" or "false" string (only apply when explicitly set)
		cfg.Signature.AdvertiseHTTPRequestSignatures = *f.SignatureAdvertiseHTTPReqSigs == "true"
	}
	if f.SignaturePeerProfileOverride != nil && *f.SignaturePeerProfileOverride != "" {
		cfg.Signature.PeerProfileLevelOverride = *f.SignaturePeerProfileOverride
	}
	if f.TLSMode != nil && *f.TLSMode != "" {
		cfg.TLS.Mode = *f.TLSMode
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
	if f.LoggingAllowSensitive != nil && *f.LoggingAllowSensitive != "" {
		// Parse "true" or "false" string (only apply when explicitly set)
		cfg.Logging.AllowSensitive = *f.LoggingAllowSensitive == "true"
	}
	if f.TokenExchangeEnabled != nil && *f.TokenExchangeEnabled != "" {
		// Parse "true" or "false" string (only apply when explicitly set)
		enabled := *f.TokenExchangeEnabled == "true"
		cfg.TokenExchange.Enabled = &enabled
	}
	if f.TokenExchangePath != nil && *f.TokenExchangePath != "" {
		cfg.TokenExchange.Path = *f.TokenExchangePath
	}
	if f.WebDAVTokenExchangeMode != nil && *f.WebDAVTokenExchangeMode != "" {
		cfg.WebDAVTokenExchange.Mode = *f.WebDAVTokenExchangeMode
	}
}

// validateEnums validates enum-like config fields and returns an error for invalid values.
func validateEnums(cfg *Config) error {
	// mode is already validated by ParseMode before we get here

	// tls.mode
	switch cfg.TLS.Mode {
	case "off", "static", "selfsigned", "acme":
		// valid
	default:
		return fmt.Errorf("invalid tls.mode %q: must be one of off, static, selfsigned, acme", cfg.TLS.Mode)
	}

	// outbound_http.ssrf_mode
	switch cfg.OutboundHTTP.SSRFMode {
	case "strict", "off":
		// valid
	default:
		return fmt.Errorf("invalid outbound_http.ssrf_mode %q: must be one of strict, off", cfg.OutboundHTTP.SSRFMode)
	}

	// signature.inbound_mode
	switch cfg.Signature.InboundMode {
	case "off", "lenient", "strict":
		// valid
	default:
		return fmt.Errorf("invalid signature.inbound_mode %q: must be one of off, lenient, strict", cfg.Signature.InboundMode)
	}

	// signature.outbound_mode
	switch cfg.Signature.OutboundMode {
	case "off", "token-only", "criteria-only", "strict":
		// valid
	default:
		return fmt.Errorf("invalid signature.outbound_mode %q: must be one of off, token-only, criteria-only, strict", cfg.Signature.OutboundMode)
	}

	// signature.peer_profile_level_override
	switch cfg.Signature.PeerProfileLevelOverride {
	case "off", "non-strict", "all":
		// valid
	default:
		return fmt.Errorf("invalid signature.peer_profile_level_override %q: must be one of off, non-strict, all", cfg.Signature.PeerProfileLevelOverride)
	}

	// guardrail: inbound_mode=off implies advertise=false
	if cfg.Signature.InboundMode == "off" && cfg.Signature.AdvertiseHTTPRequestSignatures {
		return fmt.Errorf("signature.advertise_http_request_signatures cannot be true when signature.inbound_mode is off")
	}

	// signature.on_discovery_error
	switch cfg.Signature.OnDiscoveryError {
	case "reject", "allow":
		// valid
	default:
		return fmt.Errorf("invalid signature.on_discovery_error %q: must be one of reject, allow", cfg.Signature.OnDiscoveryError)
	}

	// cache.driver (empty defaults to memory)
	switch cfg.Cache.Driver {
	case "", "memory", "redis":
		// valid (empty defaults to memory)
	default:
		return fmt.Errorf("invalid cache.driver %q: must be one of memory or redis", cfg.Cache.Driver)
	}

	// peer trust validation
	if cfg.PeerTrust.Enabled {
		// config_paths must be non-empty when peer trust is enabled
		if len(cfg.PeerTrust.ConfigPaths) == 0 {
			return fmt.Errorf("peer_trust.config_paths must be non-empty when peer trust is enabled")
		}
		// each path must be readable
		for _, path := range cfg.PeerTrust.ConfigPaths {
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("peer_trust config path %q is not readable: %w", path, err)
			}
		}
	}

	// logging.level validation
	switch cfg.Logging.Level {
	case "trace", "debug", "info", "warn", "error":
		// valid
	default:
		return fmt.Errorf("invalid logging.level %q: must be one of trace, debug, info, warn, error", cfg.Logging.Level)
	}

	// token_exchange.path validation (if path is set)
	if cfg.TokenExchange.Path != "" {
		path := cfg.TokenExchange.Path
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("invalid token_exchange.path: must not be empty")
		}
		if strings.Contains(path, "..") {
			return fmt.Errorf("invalid token_exchange.path: must not contain '..'")
		}
		if strings.HasPrefix(path, "/") {
			return fmt.Errorf("invalid token_exchange.path: must be relative (no leading slash)")
		}
		if strings.Contains(path, "://") {
			return fmt.Errorf("invalid token_exchange.path: must not contain a scheme")
		}
	}

	// webdav_token_exchange.mode validation
	switch cfg.WebDAVTokenExchange.Mode {
	case "off", "lenient", "strict":
		// valid
	default:
		return fmt.Errorf("invalid webdav_token_exchange.mode %q: must be one of off, lenient, strict", cfg.WebDAVTokenExchange.Mode)
	}

	// http.interceptors.ratelimit validation (fail fast)
	if err := validateRatelimitConfig(cfg); err != nil {
		return err
	}

	return nil
}

// validateRatelimitConfig validates ratelimit interceptor configuration.
// Profiles are defined at [http.interceptors.ratelimit.profiles.<name>].
// Services opt-in via [http.services.<svc>.ratelimit] with profile = "<name>".
// If a service references a profile, that profile must exist.
func validateRatelimitConfig(cfg *Config) error {
	// Collect available profile names from http.interceptors.ratelimit.profiles
	profiles := make(map[string]bool)
	if cfg.HTTP.Interceptors != nil {
		if rlCfg, ok := cfg.HTTP.Interceptors["ratelimit"]; ok {
			if profilesRaw, ok := rlCfg["profiles"]; ok {
				if profilesMap, ok := profilesRaw.(map[string]any); ok {
					for name, profile := range profilesMap {
						// Each profile must be a map
						if _, ok := profile.(map[string]any); !ok {
							return fmt.Errorf("http.interceptors.ratelimit.profiles.%s must be a map", name)
						}
						profiles[name] = true
					}
				} else {
					return fmt.Errorf("http.interceptors.ratelimit.profiles must be a map")
				}
			}
		}
	}

	// Validate per-service ratelimit references
	if cfg.HTTP.Services != nil {
		for svcName, svcCfg := range cfg.HTTP.Services {
			if rlCfg, ok := svcCfg["ratelimit"]; ok {
				if rlMap, ok := rlCfg.(map[string]any); ok {
					if profileName, ok := rlMap["profile"]; ok {
						if profileStr, ok := profileName.(string); ok {
							if !profiles[profileStr] {
								return fmt.Errorf("http.services.%s.ratelimit references undefined profile %q", svcName, profileStr)
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// validatePublicOrigin checks the public_origin config value when set.
// Must be an absolute URL with http/https scheme, a host, no userinfo,
// query, fragment, or base path. Whitespace is rejected, not trimmed.
func validatePublicOrigin(cfg *Config) error {
	if cfg.PublicOrigin == "" {
		return nil
	}

	origin := cfg.PublicOrigin

	if origin != strings.TrimSpace(origin) {
		return fmt.Errorf("invalid public_origin %q: must not contain leading or trailing whitespace", origin)
	}

	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid public_origin %q: %w", origin, err)
	}

	if !u.IsAbs() {
		return fmt.Errorf("invalid public_origin %q: must be an absolute URL with http or https scheme", origin)
	}

	switch u.Scheme {
	case "http", "https":
		// valid
	default:
		return fmt.Errorf("invalid public_origin %q: scheme must be http or https, got %q", origin, u.Scheme)
	}

	if u.Host == "" {
		return fmt.Errorf("invalid public_origin %q: must include a host", origin)
	}

	if u.User != nil {
		return fmt.Errorf("invalid public_origin %q: must not include userinfo", origin)
	}

	if u.RawQuery != "" {
		return fmt.Errorf("invalid public_origin %q: must not include a query string", origin)
	}

	if u.Fragment != "" {
		return fmt.Errorf("invalid public_origin %q: must not include a fragment", origin)
	}

	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("invalid public_origin %q: must not include a path (use external_base_path for base path)", origin)
	}

	return nil
}
