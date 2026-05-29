package config

import (
	"fmt"
	"strings"
)

// Mode represents the server operating mode.
type Mode string

const (
	ModeStrict  Mode = "strict"
	ModeCompat  Mode = "compat"
	ModeDev     Mode = "dev"
	ModeInterop      = ModeCompat
)

// ParseMode parses a mode string, returning an error for invalid values.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict", "":
		return ModeStrict, nil
	case "compat", "interop":
		return ModeCompat, nil
	case "dev":
		return ModeDev, nil
	default:
		return "", fmt.Errorf("invalid mode %q: must be one of strict, compat, dev", s)
	}
}

// presetForMode returns the base config for a given mode.
func presetForMode(mode Mode) *Config {
	switch mode {
	case ModeDev:
		return DevConfig()
	case ModeCompat:
		return CompatConfig()
	default:
		return StrictConfig()
	}
}

// StrictConfig returns production-safe strict defaults.
func StrictConfig() *Config {
	tokenExchangeEnabled := true
	return &Config{
		Mode:               string(ModeStrict),
		CompatibilityScope: "none",
		PublicOrigin:       "https://localhost:9200",
		ExternalBasePath:   "",
		ListenAddr:         ":9200",
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
			SSRF:               SSRFConfig{Mode: "strict"},
			SSRFMode:           "strict",
			TimeoutMS:          10000,
			ConnectTimeoutMS:   2000,
			MaxRedirects:       1,
			MaxResponseBytes:   1048576,
			InsecureSkipVerify: false,
			ProxyEnvFallback:   true,
		},
		Signature: SignatureConfig{
			InboundMode:              "strict",
			OutboundMode:             "strict",
			PeerProfileLevelOverride: "off",
			KeyPath:                  ".ocm/keys/signing.pem",
			OnDiscoveryError:         "reject",
			AllowMismatch:            false,
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
			Enabled: &tokenExchangeEnabled,
			Path:    "token",
		},
		RequireTokenExchange: true,
		PeerPolicy:           "strict",
	}
}

// CompatConfig returns compatibility mode defaults.
func CompatConfig() *Config {
	cfg := StrictConfig()
	cfg.Mode = string(ModeCompat)
	cfg.CompatibilityScope = "unbounded"
	cfg.Signature.InboundMode = "lenient"
	cfg.Signature.OutboundMode = "criteria-only"
	cfg.Signature.PeerProfileLevelOverride = "non-strict"
	cfg.RequireTokenExchange = false
	cfg.PeerPolicy = "prefer-strict"
	// InsecureSkipVerify stays configurable (default false)
	return cfg
}

// DevConfig returns development mode defaults as an overlay on StrictConfig,
// so the strict preset stays the single source of shared defaults. Each call
// builds a fresh StrictConfig, so the token-exchange enabled pointer is unique
// per DevConfig call and is not aliased across separate preset calls.
func DevConfig() *Config {
	cfg := StrictConfig()
	cfg.Mode = string(ModeDev)
	cfg.CompatibilityScope = "unbounded"
	cfg.TLS.Mode = "off"
	cfg.TLS.ACME.Directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
	cfg.TLS.ACME.UseStaging = true
	cfg.OutboundHTTP.SSRF.Mode = "off"
	cfg.OutboundHTTP.SSRFMode = "off"
	cfg.OutboundHTTP.MaxRedirects = 3
	cfg.OutboundHTTP.InsecureSkipVerify = true
	cfg.OutboundHTTP.ProxyEnvFallback = false
	cfg.Signature.InboundMode = "lenient"
	cfg.Signature.OutboundMode = "criteria-only"
	cfg.Signature.PeerProfileLevelOverride = "non-strict"
	cfg.Signature.OnDiscoveryError = "allow"
	cfg.Signature.AllowMismatch = true
	cfg.Logging.Level = "debug"
	cfg.RequireTokenExchange = false
	cfg.PeerPolicy = "prefer-strict"
	return cfg
}
