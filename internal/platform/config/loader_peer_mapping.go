// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// normalizePeerMappingConfig canonicalizes host keys in [ocm.peer_compat] using
// the public origin scheme. It must run after config overlays are applied.
func normalizePeerMappingConfig(cfg *Config) error {
	if cfg.OCM.PeerMapping.HostPlatform == nil && len(cfg.OCM.PeerMapping.Platform) == 0 {
		return nil
	}

	scheme := cfg.PublicScheme()

	cfg.OCM.PeerMapping.scheme = scheme
	if len(cfg.OCM.PeerMapping.HostPlatform) > 0 {
		normalized := make(map[string]string, len(cfg.OCM.PeerMapping.HostPlatform))
		for host, platform := range cfg.OCM.PeerMapping.HostPlatform {
			norm, err := hostport.Normalize(host, scheme)
			if err != nil {
				return fmt.Errorf("host_platform key %q: %w", host, err)
			}

			if _, exists := normalized[norm]; exists {
				return fmt.Errorf("duplicate normalized host %q", norm)
			}

			normalized[norm] = platform
		}

		cfg.OCM.PeerMapping.HostPlatform = normalized
	}

	for platformName, overlay := range cfg.OCM.PeerMapping.Platform {
		if len(overlay.Instance) == 0 {
			continue
		}

		normalizedInstances := make(map[string]PeerMappingInstanceOverlay, len(overlay.Instance))
		for host, instance := range overlay.Instance {
			norm, err := hostport.Normalize(host, scheme)
			if err != nil {
				return fmt.Errorf("platform.%s.instance key %q: %w", platformName, host, err)
			}

			if _, exists := normalizedInstances[norm]; exists {
				return fmt.Errorf("duplicate normalized host %q", norm)
			}

			normalizedInstances[norm] = instance
		}

		cfg.OCM.PeerMapping.Platform[platformName] = PeerPlatformOverlay{
			IncludesTokenExchangeRequirement: overlay.IncludesTokenExchangeRequirement,
			RequiresTokenExchangeRequirement: overlay.RequiresTokenExchangeRequirement,
			Instance:                         normalizedInstances,
		}
	}

	return nil
}

// validatePeerMappingConfig rejects duplicate host bindings across instance
// and host_platform maps after normalization.
func validatePeerMappingConfig(cfg *Config) error {
	seen := make(map[string]struct{})

	for platformName, overlay := range cfg.OCM.PeerMapping.Platform {
		for host := range overlay.Instance {
			if _, exists := seen[host]; exists {
				return fmt.Errorf("duplicate host binding %q (platform %s instance)", host, platformName)
			}

			seen[host] = struct{}{}
		}
	}

	for host, platform := range cfg.OCM.PeerMapping.HostPlatform {
		if _, exists := seen[host]; exists {
			return fmt.Errorf("duplicate host binding %q (host_platform maps to %s)", host, platform)
		}

		seen[host] = struct{}{}
	}

	return nil
}
