// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

// PeerMappingConfig holds the hierarchical [ocm.peer_compat] overlay.
// Empty TOML leaves all *bool knobs nil, which defaults to strict (true).
// Maps are normalized at load time so host lookup is scheme-aware.
type PeerMappingConfig struct {
	IncludesTokenExchangeRequirement *bool `toml:"includes_token_exchange_requirement"`
	RequiresTokenExchangeRequirement *bool `toml:"requires_token_exchange_requirement"`
	RequiresHTTPRequestSignatures    *bool `toml:"requires_http_request_signatures"`

	HostPlatform map[string]string              `toml:"host_platform"`
	Platform     map[string]PeerPlatformOverlay `toml:"platform"`

	scheme string
}

// PublicScheme returns the scheme used to normalize host keys.
// It defaults to "https" when the config has not been loaded.
func (cfg *PeerMappingConfig) PublicScheme() string {
	if cfg.scheme == "" {
		return schemeHTTPS
	}

	return cfg.scheme
}

// Scheme returns the scheme for host-key normalization.
func (cfg *PeerMappingConfig) Scheme() string {
	return cfg.PublicScheme()
}

// PeerPlatformOverlay holds platform-level knobs and per-instance overrides.
// HTTP request signature admission is governed by the must-use-http-sig
// criterion and Applicability rules, not by per-peer compatibility knobs.
type PeerPlatformOverlay struct {
	IncludesTokenExchangeRequirement *bool `toml:"includes_token_exchange_requirement"`
	RequiresTokenExchangeRequirement *bool `toml:"requires_token_exchange_requirement"`

	Instance map[string]PeerMappingInstanceOverlay `toml:"instance"`
}

// PeerMappingInstanceOverlay holds instance-level knob overrides.
// HTTP request signature admission is governed by the must-use-http-sig
// criterion and Applicability rules, not by per-peer compatibility knobs.
type PeerMappingInstanceOverlay struct {
	IncludesTokenExchangeRequirement *bool `toml:"includes_token_exchange_requirement"`
	RequiresTokenExchangeRequirement *bool `toml:"requires_token_exchange_requirement"`
}

// GlobalKnobs returns the global tier knobs.
func (cfg *PeerMappingConfig) GlobalKnobs() (includes, requires, http *bool) {
	return cfg.IncludesTokenExchangeRequirement, cfg.RequiresTokenExchangeRequirement, cfg.RequiresHTTPRequestSignatures
}

// HostPlatformFor returns the platform mapped to host, if any.
func (cfg *PeerMappingConfig) HostPlatformFor(host string) (string, bool) {
	platform, ok := cfg.HostPlatform[host]

	return platform, ok
}

// PlatformInstanceBinding returns the platform that has an explicit instance
// binding for host, if any.
func (cfg *PeerMappingConfig) PlatformInstanceBinding(host string) (string, bool) {
	for platform, overlay := range cfg.Platform {
		if overlay.Instance == nil {
			continue
		}

		if _, ok := overlay.Instance[host]; ok {
			return platform, true
		}
	}

	return "", false
}

// PlatformKnobs returns the platform-level knobs, if the platform is defined.
func (cfg *PeerMappingConfig) PlatformKnobs(platform string) (includes, requires *bool, ok bool) {
	overlay, ok := cfg.Platform[platform]
	if !ok {
		return nil, nil, false
	}

	return overlay.IncludesTokenExchangeRequirement, overlay.RequiresTokenExchangeRequirement, true
}

// InstanceKnobs returns the instance-level knobs for a platform and host, if
// both are defined.
func (cfg *PeerMappingConfig) InstanceKnobs(platform, host string) (includes, requires *bool, ok bool) {
	overlay, ok := cfg.Platform[platform]
	if !ok {
		return nil, nil, false
	}

	inst, ok := overlay.Instance[host]
	if !ok {
		return nil, nil, false
	}

	return inst.IncludesTokenExchangeRequirement, inst.RequiresTokenExchangeRequirement, true
}
