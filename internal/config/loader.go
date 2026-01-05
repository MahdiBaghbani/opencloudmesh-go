// Package config provides configuration loading and validation.
package config

import (
	"fmt"
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
//
// If ConfigPath is provided but the file is missing, unreadable, or invalid TOML,
// Load returns an error (fail fast).
func Load(opts LoaderOptions) (*Config, error) {
	var fc fileConfig

	// Step 1: Load TOML file if provided
	if opts.ConfigPath != "" {
		data, err := os.ReadFile(opts.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", opts.ConfigPath, err)
		}
		if _, err := toml.Decode(string(data), &fc); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", opts.ConfigPath, err)
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
