// Package config provides configuration loading and validation.
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
		return "https"
	}
	return cfg.scheme
}

// Scheme returns the scheme for host-key normalization.
func (cfg *PeerMappingConfig) Scheme() string {
	return cfg.PublicScheme()
}

// PeerPlatformOverlay holds platform-level knobs and per-instance overrides.
type PeerPlatformOverlay struct {
	IncludesTokenExchangeRequirement *bool `toml:"includes_token_exchange_requirement"`
	RequiresTokenExchangeRequirement *bool `toml:"requires_token_exchange_requirement"`
	RequiresHTTPRequestSignatures    *bool `toml:"requires_http_request_signatures"`

	Instance map[string]PeerMappingInstanceOverlay `toml:"instance"`
}

// PeerMappingInstanceOverlay holds instance-level knob overrides.
type PeerMappingInstanceOverlay struct {
	IncludesTokenExchangeRequirement *bool `toml:"includes_token_exchange_requirement"`
	RequiresTokenExchangeRequirement *bool `toml:"requires_token_exchange_requirement"`
	RequiresHTTPRequestSignatures    *bool `toml:"requires_http_request_signatures"`
}

// GlobalKnobs returns the global tier knobs.
func (c *PeerMappingConfig) GlobalKnobs() (includes, requires, http *bool) {
	return c.IncludesTokenExchangeRequirement, c.RequiresTokenExchangeRequirement, c.RequiresHTTPRequestSignatures
}

// HostPlatformFor returns the platform mapped to host, if any.
func (c *PeerMappingConfig) HostPlatformFor(host string) (string, bool) {
	platform, ok := c.HostPlatform[host]
	return platform, ok
}

// PlatformInstanceBinding returns the platform that has an explicit instance
// binding for host, if any.
func (c *PeerMappingConfig) PlatformInstanceBinding(host string) (string, bool) {
	for platform, overlay := range c.Platform {
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
func (c *PeerMappingConfig) PlatformKnobs(platform string) (includes, requires, http *bool, ok bool) {
	overlay, ok := c.Platform[platform]
	if !ok {
		return nil, nil, nil, false
	}
	return overlay.IncludesTokenExchangeRequirement, overlay.RequiresTokenExchangeRequirement, overlay.RequiresHTTPRequestSignatures, true
}

// InstanceKnobs returns the instance-level knobs for a platform and host, if
// both are defined.
func (c *PeerMappingConfig) InstanceKnobs(platform, host string) (includes, requires, http *bool, ok bool) {
	overlay, ok := c.Platform[platform]
	if !ok {
		return nil, nil, nil, false
	}
	inst, ok := overlay.Instance[host]
	if !ok {
		return nil, nil, nil, false
	}
	return inst.IncludesTokenExchangeRequirement, inst.RequiresTokenExchangeRequirement, inst.RequiresHTTPRequestSignatures, true
}
