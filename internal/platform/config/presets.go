// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"fmt"
	"strings"
)

// Mode represents the server operating mode.
type Mode string

const (
	// ModeStrict is the strict server operating mode.
	ModeStrict Mode = "strict"
	// ModeDev is the development server operating mode.
	ModeDev Mode = "dev"
)

// CompatibilityScope selects how peer-compat leniency is applied.
// This is an ocmgo-internal policy axis, not an OCM specification concept.
type CompatibilityScope string

const (
	// CompatibilityScopeGlobal applies peer_compat relaxations globally (current behavior).
	CompatibilityScopeGlobal CompatibilityScope = "global"
	// CompatibilityScopeScoped limits leniency to explicitly mapped peers only.
	CompatibilityScopeScoped CompatibilityScope = "scoped"
)

// ParseCompatibilityScope parses a compatibility_scope string.
func ParseCompatibilityScope(s string) (CompatibilityScope, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "global", "":
		return CompatibilityScopeGlobal, nil
	case "scoped":
		return CompatibilityScopeScoped, nil
	default:
		return "", fmt.Errorf("invalid ocm.compatibility_scope %q: must be one of global, scoped", s)
	}
}

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
	//nolint:exhaustive // ModeStrict intentionally folds into the default strict preset
	switch mode {
	case ModeDev:
		return DevConfig()
	default:
		return StrictConfig()
	}
}

// StrictConfig returns production-safe strict defaults.
func StrictConfig() *Config {
	cfg := &Config{
		Mode:             string(ModeStrict),
		PublicOrigin:     fmt.Sprintf("https://localhost:%d", defaultStrictHTTPSPort),
		ExternalBasePath: "",
		ListenAddr:       fmt.Sprintf(":%d", defaultStrictHTTPSPort),
		Server: ServerConfig{
			TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		},
		TLS: TLSConfig{
			Mode:          "selfsigned",
			HTTPPort:      defaultStrictHTTPPort,
			HTTPSPort:     defaultStrictHTTPSPort,
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
			Level: "info",
		},
		TokenExchange: TokenExchangeConfig{
			Path: "token",
		},
		Persistence: PersistenceConfig{
			Backend: BackendSQLite,
			DataDir: DefaultPersistenceDataDir,
		},
		OCM: OCMConfig{
			CompatibilityScope: CompatibilityScopeGlobal,
			// Discovery defaults accept any peer apiVersion with a warning on
			// differences. This is intentional ocmgo posture, not a spec
			// requirement: apiVersion is a REQUIRED discovery field in OCM, but the
			// spec does not mandate version-matching or rejection behavior, so
			// strict-by-default rejection is not required.
			// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L630-L631
			Discovery: DefaultDiscoveryConfig(),
		},
	}
	if err := normalizeSignatureConfig(&cfg.Signature); err != nil {
		// Built-in defaults must already be canonical.
		panic("config.StrictConfig: " + err.Error())
	}

	return cfg
}

// DevConfig returns development mode defaults as an overlay on StrictConfig,
// so the strict preset stays the single source of shared defaults.
//
// DevConfig relaxes dev-only transport and operational settings (TLS off, SSRF
// off, insecure skip verify, ACME staging, debug logging) and overrides
// persistence to the ephemeral memory backend so dev runs never touch the
// strict data dir.
func DevConfig() *Config {
	cfg := StrictConfig()
	cfg.Mode = string(ModeDev)
	cfg.TLS.Mode = tlsModeOff
	cfg.TLS.ACME.Directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
	cfg.TLS.ACME.UseStaging = true
	cfg.OutboundHTTP.SSRF.Mode = ssrfModeOff
	cfg.OutboundHTTP.MaxRedirects = 3
	cfg.OutboundHTTP.InsecureSkipVerify = true
	cfg.OutboundHTTP.UseEnvFallback = false
	cfg.Logging.Level = "debug"
	cfg.Persistence.Backend = BackendMemory
	cfg.Persistence.DataDir = ""

	return cfg
}
