// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

func validateTLSMode(cfg *Config) error {
	switch cfg.TLS.Mode {
	case "off", "static", "selfsigned", "acme":
		return nil
	default:
		return fmt.Errorf("invalid tls.mode %q: must be one of off, static, selfsigned, acme", cfg.TLS.Mode)
	}
}

func validateSSRFMode(cfg *Config) error {
	switch cfg.OutboundHTTP.SSRF.Mode {
	case "strict", "off":
		return nil
	default:
		return fmt.Errorf("invalid outbound_http.ssrf.mode %q: must be one of strict, off", cfg.OutboundHTTP.SSRF.Mode)
	}
}

func validateSSRFRoutePolicyRef(cfg *Config) error {
	if cfg.OutboundHTTP.SSRF.RoutePolicy == "" {
		return nil
	}

	if _, ok := cfg.OutboundHTTP.SSRF.RoutePolicies[cfg.OutboundHTTP.SSRF.RoutePolicy]; !ok {
		return fmt.Errorf(
			"outbound_http.ssrf.route_policy %q references an undefined policy; define it under [outbound_http.ssrf.route_policies.%s]",
			cfg.OutboundHTTP.SSRF.RoutePolicy,
			cfg.OutboundHTTP.SSRF.RoutePolicy,
		)
	}

	return nil
}

func validateSignatureFields(cfg *Config) error {
	if cfg.Signature.Label == "" {
		return fmt.Errorf("signature.label must not be empty")
	}

	if cfg.Signature.KidFragment == "" {
		return fmt.Errorf("signature.kid_fragment must not be empty")
	}

	if cfg.Signature.CreatedMaxAgeSeconds <= 0 {
		return fmt.Errorf("signature.created_max_age_seconds must be positive")
	}

	if cfg.Signature.CreatedMaxSkewSeconds < 0 {
		return fmt.Errorf("signature.created_max_skew_seconds must be non-negative")
	}

	return nil
}

// validateSignatureJwksURI performs static validation of a configured local
// signature.jwks_uri override: absolute, http/https scheme, no credentials,
// no fragment, and https unless the local public origin itself opts into
// development HTTP transport. It intentionally does not check same-authority
// against the resolved discovery endpoint; that check runs in wiring.Build
// (discovery.ValidateLocalJwksURIOverride) once the endpoint authority is
// known, reusing the same policy enforced for peer-advertised jwksUri so the
// two paths never diverge.
func validateSignatureJwksURI(cfg *Config) error {
	raw := cfg.Signature.JwksURI
	if raw == "" {
		return nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid signature.jwks_uri: malformed")
	}

	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid signature.jwks_uri: must be absolute")
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return fmt.Errorf("invalid signature.jwks_uri: scheme %q is not allowed", u.Scheme)
	}

	if scheme == "http" && cfg.PublicScheme() != "http" {
		return fmt.Errorf("invalid signature.jwks_uri: must use https outside development HTTP opt-in")
	}

	if u.User != nil {
		return fmt.Errorf("invalid signature.jwks_uri: must not contain credentials")
	}

	// Bare "#" leaves Fragment empty after url.Parse; reject any fragment delimiter.
	if strings.Contains(raw, "#") {
		return fmt.Errorf("invalid signature.jwks_uri: must not contain a fragment")
	}

	return nil
}

func validateCacheDriver(cfg *Config) error {
	switch cfg.Cache.Driver {
	case "", "memory", "redis":
		return nil
	default:
		return fmt.Errorf("invalid cache.driver %q: must be one of memory or redis", cfg.Cache.Driver)
	}
}

func validatePeerTrust(cfg *Config) error {
	if !cfg.PeerTrust.Enabled {
		return nil
	}

	if len(cfg.PeerTrust.ConfigPaths) == 0 {
		return fmt.Errorf("peer_trust.config_paths must be non-empty when peer trust is enabled")
	}

	for _, path := range cfg.PeerTrust.ConfigPaths {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("peer_trust config path %q is not readable: %w", path, err)
		}
	}

	return nil
}

func validateLoggingLevel(cfg *Config) error {
	switch cfg.Logging.Level {
	case "trace", "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("invalid logging.level %q: must be one of trace, debug, info, warn, error", cfg.Logging.Level)
	}
}

func validateTokenExchangePath(cfg *Config) error {
	if cfg.TokenExchange.Path == "" {
		return nil
	}

	path := cfg.TokenExchange.Path
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("invalid token_exchange.path: must not be empty")
	}

	if strings.Contains(path, "..") {
		return fmt.Errorf("invalid token_exchange.path: must not contain '..'")
	}

	if strings.HasPrefix(path, "/") {
		return fmt.Errorf("invalid token_exchange.path: must be relative (no leading slash)")
	}

	if strings.Contains(path, "://") {
		return fmt.Errorf("invalid token_exchange.path: must not contain a scheme")
	}

	return nil
}

func validatePersistenceBackend(cfg *Config) error {
	switch cfg.Persistence.Backend {
	case BackendMemory, BackendJSON, BackendSQLite, BackendMirror:
		// valid
	default:
		return fmt.Errorf(
			"invalid persistence.backend %q: must be one of memory, json, sqlite, mirror",
			cfg.Persistence.Backend,
		)
	}

	if cfg.Persistence.Backend != BackendMemory && cfg.Persistence.DataDir == "" {
		return fmt.Errorf(
			"persistence.data_dir is required for backend %q",
			cfg.Persistence.Backend,
		)
	}

	return nil
}

func validateCompatibilityScope(cfg *Config) error {
	scope, err := ParseCompatibilityScope(string(cfg.OCM.CompatibilityScope))
	if err != nil {
		return err
	}

	cfg.OCM.CompatibilityScope = scope

	return nil
}

func validateDiscoveryPolicies(cfg *Config) error {
	switch cfg.OCM.Discovery.PeerAPIVersionPolicy {
	case "accept-any", "exact", "at-least-1.4":
		// valid
	default:
		return fmt.Errorf(
			"invalid ocm.discovery.peer_api_version_policy %q: must be one of accept-any, exact, at-least-1.4",
			cfg.OCM.Discovery.PeerAPIVersionPolicy,
		)
	}

	switch cfg.OCM.Discovery.PeerAPIVersionWarn {
	case "any-diff", "lower-only", "none":
		// valid
	default:
		return fmt.Errorf(
			"invalid ocm.discovery.peer_api_version_warn %q: must be one of any-diff, lower-only, none",
			cfg.OCM.Discovery.PeerAPIVersionWarn,
		)
	}

	return nil
}

// validateEnums validates enum-like config fields and returns an error for invalid values.
func validateEnums(cfg *Config) error {
	// mode is already validated by ParseMode before we get here
	validators := []func(*Config) error{
		validateTLSMode,
		validateSSRFMode,
		validateSSRFRoutePolicyRef,
		validateSignatureFields,
		validateSignatureJwksURI,
		validateCacheDriver,
		validatePeerTrust,
		validateLoggingLevel,
		validateTokenExchangePath,
		validatePersistenceBackend,
		validateCompatibilityScope,
		validateDiscoveryPolicies,
		validateSSRFRoutePolicyGuardrails,
		validateStrictModeGuardrails,
		validateRatelimitConfig,
	}

	for _, validator := range validators {
		if err := validator(cfg); err != nil {
			return err
		}
	}

	return nil
}

// ValidateStrictModeStartupGuardrails applies the same strict-mode startup
// guardrails that Load enforces. It is exported so in-memory config callers
// that build a Config without going through Load (for example the in-process
// test harness) reject the same impossible startup states the real binary
// rejects. Load reaches this logic via validateEnums.
func ValidateStrictModeStartupGuardrails(cfg *Config) error {
	return validateStrictModeGuardrails(cfg)
}

func validateStrictModeGuardrails(cfg *Config) error {
	if cfg == nil || cfg.Mode != "strict" {
		return nil
	}

	if !cfg.OCM.MustInviteEnforced() {
		return fmt.Errorf("mode=strict requires ocm.invite.enforce_must_invite!=false")
	}

	if cfg.TLS.Mode == "off" {
		return fmt.Errorf("mode=strict requires tls.mode!=off")
	}

	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		return fmt.Errorf("mode=strict requires outbound_http.ssrf.mode=strict")
	}

	if cfg.OutboundHTTP.InsecureSkipVerify {
		return fmt.Errorf("mode=strict requires outbound_http.insecure_skip_verify=false")
	}

	return nil
}
