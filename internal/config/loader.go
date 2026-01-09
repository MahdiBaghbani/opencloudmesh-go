// Package config provides configuration loading and validation.
package config

import (
	"fmt"
	"log/slog"
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
	ListenAddr       *string
	ExternalOrigin   *string
	ExternalBasePath *string
	SSRFMode         *string
	SignaturePolicy  *string
	TLSMode          *string
	AdminUsername    *string
	AdminPassword    *string
}

// fileConfig mirrors Config but with pointer fields to detect presence.
type fileConfig struct {
	Mode   string        `toml:"mode"`
	Server *serverConfig `toml:"server"`

	ExternalOrigin   string `toml:"external_origin"`
	ExternalBasePath string `toml:"external_base_path"`
	ListenAddr       string `toml:"listen_addr"`

	TLS          *TLSConfig          `toml:"tls"`
	OutboundHTTP *OutboundHTTPConfig `toml:"outbound_http"`
	Signature    *SignatureConfig    `toml:"signature"`
	PeerProfiles *peerProfilesConfig `toml:"peer_profiles"`
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

		// Warn about undecoded keys (do not fail)
		if undecoded := md.Undecoded(); len(undecoded) > 0 {
			keys := make([]string, len(undecoded))
			for i, k := range undecoded {
				keys[i] = k.String()
			}
			logger.Warn("config file contains undecoded keys", "path", opts.ConfigPath, "keys", keys)
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

	return cfg, nil
}

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
		ExternalOrigin:   "https://localhost:9200",
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
			Mode:             "strict",
			KeyPath:          ".ocm/keys/signing.pem",
			OnDiscoveryError: "reject",
			AllowMismatch:    false,
		},
	}
}

// InteropConfig returns interop mode defaults.
func InteropConfig() *Config {
	cfg := StrictConfig()
	cfg.Mode = string(ModeInterop)
	cfg.Signature.Mode = "lenient"
	// InsecureSkipVerify stays configurable (default false)
	return cfg
}

// DevConfig returns development mode defaults.
func DevConfig() *Config {
	return &Config{
		Mode:             string(ModeDev),
		ExternalOrigin:   "https://localhost:9200",
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
			Mode:             "lenient",
			KeyPath:          ".ocm/keys/signing.pem",
			OnDiscoveryError: "allow",
			AllowMismatch:    true,
		},
	}
}

// overlayFileConfig applies TOML file values onto cfg.
func overlayFileConfig(cfg *Config, fc *fileConfig) {
	if fc.ExternalOrigin != "" {
		cfg.ExternalOrigin = fc.ExternalOrigin
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
		if fc.Signature.Mode != "" {
			cfg.Signature.Mode = fc.Signature.Mode
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
}

// overlayFlags applies CLI flag values onto cfg.
func overlayFlags(cfg *Config, f FlagOverrides) {
	if f.ListenAddr != nil && *f.ListenAddr != "" {
		cfg.ListenAddr = *f.ListenAddr
	}
	if f.ExternalOrigin != nil && *f.ExternalOrigin != "" {
		cfg.ExternalOrigin = *f.ExternalOrigin
	}
	if f.ExternalBasePath != nil && *f.ExternalBasePath != "" {
		cfg.ExternalBasePath = *f.ExternalBasePath
	}
	if f.SSRFMode != nil && *f.SSRFMode != "" {
		cfg.OutboundHTTP.SSRFMode = *f.SSRFMode
	}
	if f.SignaturePolicy != nil && *f.SignaturePolicy != "" {
		cfg.Signature.Mode = *f.SignaturePolicy
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

	// signature.mode
	switch cfg.Signature.Mode {
	case "off", "lenient", "strict":
		// valid
	default:
		return fmt.Errorf("invalid signature.mode %q: must be one of off, lenient, strict", cfg.Signature.Mode)
	}

	// signature.on_discovery_error
	switch cfg.Signature.OnDiscoveryError {
	case "reject", "allow":
		// valid
	default:
		return fmt.Errorf("invalid signature.on_discovery_error %q: must be one of reject, allow", cfg.Signature.OnDiscoveryError)
	}

	return nil
}
