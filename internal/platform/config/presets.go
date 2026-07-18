package config

import (
	"fmt"
	"strings"
)

// Mode represents the server operating mode.
type Mode string

const (
	ModeStrict Mode = "strict"
	ModeDev    Mode = "dev"
)

// ParseMode parses a mode string, returning an error for invalid values.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict", "":
		return ModeStrict, nil
	case "dev":
		return ModeDev, nil
	default:
		return "", fmt.Errorf("invalid mode %q: must be one of strict, dev", s)
	}
}

// presetForMode returns the base config for a given mode.
func presetForMode(mode Mode) *Config {
	switch mode {
	case ModeDev:
		return DevConfig()
	default:
		return StrictConfig()
	}
}

// StrictConfig returns production-safe strict defaults.
func StrictConfig() *Config {
	tokenExchangeEnabled := true
	cfg := &Config{
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
		OutboundHTTP: DefaultOutboundHTTP(),
		Signature:    DefaultSignatureConfig(),
		PeerTrust: PeerTrustConfig{
			Enabled:         false,
			ConfigPaths:     nil,
			MembershipCache: DefaultPeerTrustMembershipCache(),
		},
		Logging: LoggingConfig{
			Level:          "info",
			AllowSensitive: false,
		},
		TokenExchange: TokenExchangeConfig{
			Enabled: &tokenExchangeEnabled,
			Path:    "token",
		},
		PeerPolicy: "strict",
		Persistence: PersistenceConfig{
			Backend: BackendMemory,
		},
	}
	if err := normalizeSignatureConfig(&cfg.Signature); err != nil {
		// Built-in defaults must already be canonical.
		panic("config.StrictConfig: " + err.Error())
	}
	return cfg
}

// DevConfig returns development mode defaults as an overlay on StrictConfig,
// so the strict preset stays the single source of shared defaults. Each call
// builds a fresh StrictConfig, so the token-exchange enabled pointer is unique
// per DevConfig call and is not aliased across separate preset calls.
//
// DevConfig is bounded scoped governance with a strict global OCM posture.
// Only dev-only transport and operational settings differ (TLS off, SSRF off,
// insecure skip verify, ACME staging, debug logging). Legacy behavior for
// local dev/test peers comes only from explicit peer_profiles.mappings resolved
// through the peercompat gate.
func DevConfig() *Config {
	cfg := StrictConfig()
	cfg.Mode = string(ModeDev)
	cfg.CompatibilityScope = "scoped"
	cfg.TLS.Mode = "off"
	cfg.TLS.ACME.Directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
	cfg.TLS.ACME.UseStaging = true
	cfg.OutboundHTTP.SSRF.Mode = "off"
	cfg.OutboundHTTP.DerivedSSRFMode = "off"
	cfg.OutboundHTTP.MaxRedirects = 3
	cfg.OutboundHTTP.InsecureSkipVerify = true
	cfg.OutboundHTTP.ProxyEnvFallback = false
	cfg.Logging.Level = "debug"
	return cfg
}
