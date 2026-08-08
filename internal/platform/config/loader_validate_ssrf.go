// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

func validateSSRFRoutePolicyHostSuffixes(activePolicy, prefix string, policy SSRFRoutePolicyConfig) error {
	if len(policy.AllowPrivateHostSuffixes) == 0 {
		return fmt.Errorf(
			"active ssrf route policy %q requires non-empty %s.allow_private_host_suffixes",
			activePolicy, prefix,
		)
	}

	for _, suffix := range policy.AllowPrivateHostSuffixes {
		if strings.TrimSpace(suffix) == "" {
			return fmt.Errorf(
				"active ssrf route policy %q has blank entry in %s.allow_private_host_suffixes",
				activePolicy, prefix,
			)
		}
	}

	return nil
}

func validateSSRFRoutePolicyCIDREmpty(activePolicy, prefix string, policy SSRFRoutePolicyConfig) error {
	if len(policy.AllowPrivateCIDRs) == 0 {
		return fmt.Errorf(
			"active ssrf route policy %q requires non-empty %s.allow_private_cidrs",
			activePolicy, prefix,
		)
	}

	return nil
}

func validateSSRFRoutePolicyCIDRContent(activePolicy, prefix string, policy SSRFRoutePolicyConfig) error {
	for _, cidr := range policy.AllowPrivateCIDRs {
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			return fmt.Errorf(
				"active ssrf route policy %q forbids catch-all CIDR %q in %s.allow_private_cidrs",
				activePolicy, cidr, prefix,
			)
		}

		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf(
				"active ssrf route policy %q has invalid CIDR %q in %s.allow_private_cidrs: %w",
				activePolicy, cidr, prefix, err,
			)
		}
	}

	return nil
}

func validateSSRFRoutePolicyPortsEmpty(activePolicy, prefix string, policy SSRFRoutePolicyConfig) error {
	if len(policy.AllowedPorts) == 0 {
		return fmt.Errorf(
			"active ssrf route policy %q requires non-empty %s.allowed_ports",
			activePolicy, prefix,
		)
	}

	return nil
}

// validateSSRFRoutePolicyGuardrails enforces guardrails on the active route
// policy whenever route_policy is configured.
func validateSSRFRoutePolicyGuardrails(cfg *Config) error {
	activePolicy := cfg.OutboundHTTP.SSRF.RoutePolicy
	if activePolicy == "" {
		return nil
	}

	policy, ok := cfg.OutboundHTTP.SSRF.RoutePolicies[activePolicy]
	if !ok {
		// already caught by validateEnums; defensive skip
		return nil
	}

	prefix := fmt.Sprintf("outbound_http.ssrf.route_policies.%s", activePolicy)

	if err := validateSSRFRoutePolicyHostSuffixes(activePolicy, prefix, policy); err != nil {
		return err
	}

	if err := validateSSRFRoutePolicyCIDREmpty(activePolicy, prefix, policy); err != nil {
		return err
	}

	if err := validateSSRFRoutePolicyPortsEmpty(activePolicy, prefix, policy); err != nil {
		return err
	}

	if policy.AllowIPLiterals {
		return fmt.Errorf(
			"active ssrf route policy %q requires %s.allow_ip_literals=false",
			activePolicy, prefix,
		)
	}

	if err := validateSSRFRoutePolicyCIDRContent(activePolicy, prefix, policy); err != nil {
		return err
	}

	if err := validateSSRFRoutePolicyPortsContent(activePolicy, prefix, policy); err != nil {
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

// validateProxyURL checks the outbound_http.proxy_url config value when set.
// Must be an absolute http or https URL with a non-empty host and no userinfo.
// Private and loopback hosts are permitted; the proxy endpoint is always
// operator-controlled and is not subject to SSRF restrictions.
func validateProxyURL(cfg *Config) error {
	raw := cfg.OutboundHTTP.ProxyURL
	if raw == "" {
		return nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid outbound_http.proxy_url %q: %w", raw, err)
	}

	if !u.IsAbs() {
		return fmt.Errorf("invalid outbound_http.proxy_url %q: must be an absolute URL with http or https scheme", raw)
	}

	switch u.Scheme {
	case "http", "https":
		// valid
	default:
		return fmt.Errorf("invalid outbound_http.proxy_url %q: scheme must be http or https, got %q", raw, u.Scheme)
	}

	if u.Hostname() == "" {
		return fmt.Errorf("invalid outbound_http.proxy_url %q: must include a non-empty host", raw)
	}

	if u.User != nil {
		return fmt.Errorf("invalid outbound_http.proxy_url %q: must not include userinfo", raw)
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

// validateOutboundTLSPaths checks that tls_root_ca_file and tls_root_ca_dir paths exist.
func validateOutboundTLSPaths(cfg *Config) error {
	if cfg.OutboundHTTP.TLSRootCAFile != "" {
		fi, err := os.Stat(cfg.OutboundHTTP.TLSRootCAFile)
		if err != nil {
			return fmt.Errorf("outbound_http.tls_root_ca_file: %w", err)
		}

		if !fi.Mode().IsRegular() {
			return fmt.Errorf("outbound_http.tls_root_ca_file: %q is not a regular file", cfg.OutboundHTTP.TLSRootCAFile)
		}
	}

	if cfg.OutboundHTTP.TLSRootCADir != "" {
		fi, err := os.Stat(cfg.OutboundHTTP.TLSRootCADir)
		if err != nil {
			return fmt.Errorf("outbound_http.tls_root_ca_dir: %w", err)
		}

		if !fi.IsDir() {
			return fmt.Errorf("outbound_http.tls_root_ca_dir: %q is not a directory", cfg.OutboundHTTP.TLSRootCADir)
		}
	}

	return nil
}

// isUnquotedMultiSegmentInstanceKey reports whether a TOML key path represents
// an instance host under [ocm.peer_compat.platform.<platform>.instance] that
// was written without quotes and contains a dot. Valid instance field keys have
// exactly seven segments: ocm.peer_compat.platform.<platform>.instance.<host>.<field>.
func isUnquotedMultiSegmentInstanceKey(key toml.Key) bool {
	if len(key) < 8 {
		return false
	}

	if key[0] != "ocm" || key[1] != "peer_compat" || key[2] != "platform" {
		return false
	}

	if key[4] != "instance" {
		return false
	}

	return len(key) > 7
}

func validateSSRFRoutePolicyPortsContent(activePolicy, prefix string, policy SSRFRoutePolicyConfig) error {
	for _, port := range policy.AllowedPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf(
				"active ssrf route policy %q has invalid port %d in %s.allowed_ports: must be in range 1-65535",
				activePolicy, port, prefix,
			)
		}
	}

	return nil
}
