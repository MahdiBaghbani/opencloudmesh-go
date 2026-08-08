// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"fmt"
	"os"
	"strconv"
)

func overlayOCMPeerMappingConfig(cfg *Config, fc *PeerMappingConfig) {
	if fc == nil {
		return
	}

	if fc.IncludesTokenExchangeRequirement != nil {
		cfg.OCM.PeerMapping.IncludesTokenExchangeRequirement = fc.IncludesTokenExchangeRequirement
	}

	if fc.RequiresTokenExchangeRequirement != nil {
		cfg.OCM.PeerMapping.RequiresTokenExchangeRequirement = fc.RequiresTokenExchangeRequirement
	}

	if fc.RequiresHTTPRequestSignatures != nil {
		cfg.OCM.PeerMapping.RequiresHTTPRequestSignatures = fc.RequiresHTTPRequestSignatures
	}

	if len(fc.HostPlatform) > 0 {
		cfg.OCM.PeerMapping.HostPlatform = fc.HostPlatform
	}

	if len(fc.Platform) > 0 {
		cfg.OCM.PeerMapping.Platform = fc.Platform
	}
}

func overlayOCMInviteConfig(cfg *Config, fc *inviteFileConfig) {
	if fc == nil {
		return
	}

	if fc.EnforceMustInvite == nil {
		return
	}

	if cfg.OCM.Invite == nil {
		cfg.OCM.Invite = &InviteConfig{}
	}

	cfg.OCM.Invite.EnforceMustInvite = fc.EnforceMustInvite
}

func overlayOCMConfig(cfg *Config, fc *ocmFileConfig) {
	if fc == nil {
		return
	}

	overlayOCMCompatibilityScope(cfg, fc.CompatibilityScope)
	overlayOCMDiscoveryConfig(cfg, fc.Discovery)
	overlayOCMCodeFlowConfig(cfg, fc.CodeFlow)
	overlayOCMInviteConfig(cfg, fc.Invite)
	overlayOCMPeerMappingConfig(cfg, fc.PeerMapping)
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

	overlayServerConfig(cfg, fc.Server)
	overlayTLSConfig(cfg, fc.TLS)
	overlayOutboundHTTPConfig(cfg, fc.OutboundHTTP)
	overlaySignatureConfig(cfg, fc.Signature)
	overlayCacheConfig(cfg, fc.Cache)
	overlayPeerTrustConfig(cfg, fc.PeerTrust)
	overlayLoggingConfig(cfg, fc.Logging)
	overlayTokenExchangeConfig(cfg, fc.TokenExchange)
	overlayHTTPConfig(cfg, fc.HTTP)
	overlayPersistenceConfig(cfg, fc.Persistence)
	overlayOCMConfig(cfg, fc.OCM)
}

// EnvOutboundHTTPUseEnvFallback is the environment-variable name that overrides
// the outbound_http.use_env_fallback TOML key at load time via applyEnvOverrides.
// use_env_fallback has no CLI flag, so the env override sits directly above the
// TOML value in the precedence order. Exported so callers that scrub or set the
// environment (for example the integration harness hermetic blocklist) reuse
// the single canonical name instead of duplicating the raw literal.
const EnvOutboundHTTPUseEnvFallback = "OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK"

// applyEnvOverrides applies environment-variable overrides onto cfg. An env var
// overrides the TOML value for its key, and the CLI flag value when a CLI flag
// exists for that key (use_env_fallback has no CLI flag, so its env override
// applies directly on top of TOML).
func applyEnvOverrides(cfg *Config) error {
	if raw := os.Getenv(EnvOutboundHTTPUseEnvFallback); raw != "" {
		val, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf(
				"invalid %s %q: must be a boolean",
				EnvOutboundHTTPUseEnvFallback,
				raw,
			)
		}

		cfg.OutboundHTTP.UseEnvFallback = val
	}

	return nil
}

// overlayFlags applies CLI flag values onto cfg.
func overlayFlags(cfg *Config, f FlagOverrides) {
	overlayNetFlags(cfg, f)
	overlayAdminFlags(cfg, f)
	overlayLoggingFlags(cfg, f)
	overlayTokenFlags(cfg, f)
}

func overlayNetFlags(cfg *Config, f FlagOverrides) {
	if f.ListenAddr != nil && *f.ListenAddr != "" {
		cfg.ListenAddr = *f.ListenAddr
	}

	if f.PublicOrigin != nil && *f.PublicOrigin != "" {
		cfg.PublicOrigin = *f.PublicOrigin
	}

	if f.ExternalBasePath != nil && *f.ExternalBasePath != "" {
		cfg.ExternalBasePath = *f.ExternalBasePath
	}
}

func overlayAdminFlags(cfg *Config, f FlagOverrides) {
	if f.AdminUsername != nil && *f.AdminUsername != "" {
		cfg.Server.BootstrapAdmin.Username = *f.AdminUsername
	}

	if f.AdminPassword != nil && *f.AdminPassword != "" {
		cfg.Server.BootstrapAdmin.Password = *f.AdminPassword
	}
}

func overlayLoggingFlags(cfg *Config, f FlagOverrides) {
	if f.LoggingLevel != nil && *f.LoggingLevel != "" {
		cfg.Logging.Level = *f.LoggingLevel
	}
}

func overlayTokenFlags(cfg *Config, f FlagOverrides) {
	if f.TokenExchangePath != nil && *f.TokenExchangePath != "" {
		cfg.TokenExchange.Path = *f.TokenExchangePath
	}
}
