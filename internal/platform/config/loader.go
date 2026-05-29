// Package config provides configuration loading and validation.
package config

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// LoaderOptions controls how configuration is loaded.
type LoaderOptions struct {
	// ConfigPath is the path to a TOML config file (optional).
	// If provided but file is missing or invalid, loading fails.
	ConfigPath string

	// ModeFlag is the --mode flag value (overrides config file mode).
	ModeFlag string

	// FlagOverrides are CLI flag values that override config file values.
	FlagOverrides FlagOverrides

	// Logger is reserved for future use.
	Logger *slog.Logger
}

// FlagOverrides holds CLI flag values that override config file values.
type FlagOverrides struct {
	ListenAddr                   *string
	PublicOrigin                 *string
	ExternalBasePath             *string
	CompatibilityScope           *string
	SignatureInboundMode         *string
	SignatureOutboundMode        *string
	SignaturePeerProfileOverride *string
	AdminUsername                *string
	AdminPassword                *string
	LoggingLevel                 *string
	LoggingAllowSensitive        *string // "true", "false", or "" (unset)
	TokenExchangeEnabled         *string // "true", "false", or "" (unset)
	TokenExchangePath            *string
	RequireTokenExchange         *string // "true", "false", or "" (unset)
	PeerPolicy                   *string
}

// Load loads configuration with the following precedence:
//  1. Determine effective mode: --mode flag > mode in config file > default (strict)
//  2. Start from mode preset defaults
//  3. Overlay TOML config file values
//  4. Overlay CLI flags
//  5. Validate enum fields
//
// If ConfigPath is provided but the file is missing, unreadable, or invalid TOML,
// Load returns an error (fail fast). Unknown/undecoded TOML keys fail the load.
func Load(opts LoaderOptions) (*Config, error) {
	var fc fileConfig
	var md toml.MetaData

	// Step 1: Load TOML file if provided
	if opts.ConfigPath != "" {
		data, err := os.ReadFile(opts.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", opts.ConfigPath, err)
		}
		md, err = toml.Decode(string(data), &fc)
		if err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", opts.ConfigPath, err)
		}
		if undecoded := md.Undecoded(); len(undecoded) > 0 {
			keys := make([]string, 0, len(undecoded))
			for _, k := range undecoded {
				keyStr := k.String()
				// http.services and http.interceptors store nested maps as
				// map[string]any; the TOML library cannot track leaf keys
				// within untyped values, so they appear undecoded by design.
				if strings.HasPrefix(keyStr, "http.services.") ||
					strings.HasPrefix(keyStr, "http.interceptors.") {
					continue
				}
				keys = append(keys, keyStr)
			}
			if len(keys) > 0 {
				sort.Strings(keys)
				return nil, fmt.Errorf("config file %s contains unsupported keys: %s", opts.ConfigPath, strings.Join(keys, ", "))
			}
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

	// Step 5b: derive SSRFMode shim from SSRF.Mode for programmatic caller compatibility
	cfg.OutboundHTTP.SSRFMode = cfg.OutboundHTTP.SSRF.Mode

	// Step 5d: tls_dir validation and derivation
	if md.IsDefined("tls", "tls_dir") && strings.TrimSpace(cfg.TLS.TLSDir) == "" {
		return nil, fmt.Errorf("tls.tls_dir is set but empty; provide a path or remove the key")
	}
	if md.IsDefined("tls", "tls_dir") {
		tlsDir := strings.TrimSpace(cfg.TLS.TLSDir)
		if !md.IsDefined("tls", "self_signed_dir") {
			cfg.TLS.SelfSignedDir = filepath.Join(tlsDir, "certs")
		}
		if !md.IsDefined("tls", "acme", "storage_dir") {
			cfg.TLS.ACME.StorageDir = filepath.Join(tlsDir, "acme")
		}
		if !md.IsDefined("signature", "key_path") {
			cfg.Signature.KeyPath = filepath.Join(tlsDir, "keys", "signing.pem")
		}
	}

	// Step 6: Validate enum fields (fatal on invalid values)
	if err := validateEnums(cfg); err != nil {
		return nil, err
	}

	// Step 7: Validate public_origin format (fail fast on invalid URL)
	if err := validatePublicOrigin(cfg); err != nil {
		return nil, err
	}

	// Step 8: Validate outbound TLS CA paths (fail fast)
	if err := validateOutboundTLSPaths(cfg); err != nil {
		return nil, err
	}

	// Step 9: Validate outbound proxy URL (fail fast)
	if err := validateProxyURL(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validateEnums validates enum-like config fields and returns an error for invalid values.
func validateEnums(cfg *Config) error {
	// mode is already validated by ParseMode before we get here

	switch cfg.CompatibilityScope {
	case "none", "scoped", "unbounded":
		// valid
	default:
		return fmt.Errorf("invalid compatibility_scope %q: must be one of none, scoped, unbounded", cfg.CompatibilityScope)
	}

	// tls.mode
	switch cfg.TLS.Mode {
	case "off", "static", "selfsigned", "acme":
		// valid
	default:
		return fmt.Errorf("invalid tls.mode %q: must be one of off, static, selfsigned, acme", cfg.TLS.Mode)
	}

	// outbound_http.ssrf.mode
	switch cfg.OutboundHTTP.SSRF.Mode {
	case "strict", "off":
		// valid
	default:
		return fmt.Errorf("invalid outbound_http.ssrf.mode %q: must be one of strict, off", cfg.OutboundHTTP.SSRF.Mode)
	}

	// outbound_http.ssrf.route_policy must reference a defined policy
	if cfg.OutboundHTTP.SSRF.RoutePolicy != "" {
		if _, ok := cfg.OutboundHTTP.SSRF.RoutePolicies[cfg.OutboundHTTP.SSRF.RoutePolicy]; !ok {
			return fmt.Errorf(
				"outbound_http.ssrf.route_policy %q references an undefined policy; define it under [outbound_http.ssrf.route_policies.%s]",
				cfg.OutboundHTTP.SSRF.RoutePolicy,
				cfg.OutboundHTTP.SSRF.RoutePolicy,
			)
		}
	}

	// signature.inbound_mode
	switch cfg.Signature.InboundMode {
	case "off", "lenient", "strict":
		// valid
	default:
		return fmt.Errorf("invalid signature.inbound_mode %q: must be one of off, lenient, strict", cfg.Signature.InboundMode)
	}

	// signature.outbound_mode
	switch cfg.Signature.OutboundMode {
	case "off", "token-only", "criteria-only", "strict":
		// valid
	default:
		return fmt.Errorf("invalid signature.outbound_mode %q: must be one of off, token-only, criteria-only, strict", cfg.Signature.OutboundMode)
	}

	// signature.peer_profile_level_override
	switch cfg.Signature.PeerProfileLevelOverride {
	case "off", "non-strict", "all":
		// valid
	default:
		return fmt.Errorf("invalid signature.peer_profile_level_override %q: must be one of off, non-strict, all", cfg.Signature.PeerProfileLevelOverride)
	}

	// signature.on_discovery_error
	switch cfg.Signature.OnDiscoveryError {
	case "reject", "allow":
		// valid
	default:
		return fmt.Errorf("invalid signature.on_discovery_error %q: must be one of reject, allow", cfg.Signature.OnDiscoveryError)
	}

	// cache.driver (empty defaults to memory)
	switch cfg.Cache.Driver {
	case "", "memory", "redis":
		// valid (empty defaults to memory)
	default:
		return fmt.Errorf("invalid cache.driver %q: must be one of memory or redis", cfg.Cache.Driver)
	}

	// peer trust validation
	if cfg.PeerTrust.Enabled {
		// config_paths must be non-empty when peer trust is enabled
		if len(cfg.PeerTrust.ConfigPaths) == 0 {
			return fmt.Errorf("peer_trust.config_paths must be non-empty when peer trust is enabled")
		}
		// each path must be readable
		for _, path := range cfg.PeerTrust.ConfigPaths {
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("peer_trust config path %q is not readable: %w", path, err)
			}
		}
	}

	// logging.level validation
	switch cfg.Logging.Level {
	case "trace", "debug", "info", "warn", "error":
		// valid
	default:
		return fmt.Errorf("invalid logging.level %q: must be one of trace, debug, info, warn, error", cfg.Logging.Level)
	}

	// token_exchange.path validation (if path is set)
	if cfg.TokenExchange.Path != "" {
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
	}

	// peer_policy validation
	switch cfg.PeerPolicy {
	case "legacy", "prefer-strict", "strict":
		// valid
	default:
		return fmt.Errorf("invalid peer_policy %q: must be one of legacy, prefer-strict, strict", cfg.PeerPolicy)
	}

	// Cross-field: canonical receive strictness requires token exchange capability
	if cfg.RequireTokenExchange && !cfg.TokenExchangeEnabled() {
		return fmt.Errorf("require_token_exchange=true requires token_exchange.enabled=true")
	}

	// Cross-field: strict peer policy requires token exchange capability
	if cfg.PeerPolicy == "strict" && !cfg.TokenExchangeEnabled() {
		return fmt.Errorf("peer_policy=strict requires token_exchange.enabled=true")
	}

	// compatibility_scope=none is the supervising strictness contract. Reject
	// obvious contradictions here before runtime posture is derived.
	if err := validateCompatibilityScopeGuardrails(cfg); err != nil {
		return err
	}

	// http.interceptors.ratelimit validation (fail fast)
	if err := validateRatelimitConfig(cfg); err != nil {
		return err
	}

	return nil
}

// ValidateCompatibilityScopeStartupGuardrails applies the same
// compatibility-scope startup guardrails that Load enforces. It is exported so
// in-memory config callers that build a Config without going through Load (for
// example the in-process test harness) reject the same broader impossible
// startup states the real binary rejects. Load reaches this logic via
// validateEnums; both paths share validateCompatibilityScopeGuardrails.
func ValidateCompatibilityScopeStartupGuardrails(cfg *Config) error {
	return validateCompatibilityScopeGuardrails(cfg)
}

func validateCompatibilityScopeGuardrails(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	switch cfg.CompatibilityScope {
	case "none":
		return validateNoneCompatibilityScopeGuardrails(cfg)
	case "scoped":
		return validateScopedCompatibilityScopeGuardrails(cfg)
	default:
		return nil
	}
}

func validateNoneCompatibilityScopeGuardrails(cfg *Config) error {
	if cfg.Signature.InboundMode != "strict" {
		return fmt.Errorf("compatibility_scope=none requires signature.inbound_mode=strict")
	}
	if cfg.Signature.OutboundMode != "strict" {
		return fmt.Errorf("compatibility_scope=none requires signature.outbound_mode=strict")
	}
	if cfg.Signature.PeerProfileLevelOverride != "off" {
		return fmt.Errorf("compatibility_scope=none requires signature.peer_profile_level_override=off")
	}
	if cfg.Signature.OnDiscoveryError != "reject" {
		return fmt.Errorf("compatibility_scope=none requires signature.on_discovery_error=reject")
	}
	if cfg.Signature.AllowMismatch {
		return fmt.Errorf("compatibility_scope=none requires signature.allow_mismatch=false")
	}
	if !cfg.RequireTokenExchange {
		return fmt.Errorf("compatibility_scope=none requires require_token_exchange=true")
	}
	if cfg.PeerPolicy != "strict" {
		return fmt.Errorf("compatibility_scope=none requires peer_policy=strict")
	}
	if cfg.TLS.Mode == "off" {
		return fmt.Errorf("compatibility_scope=none requires tls.mode!=off")
	}
	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		return fmt.Errorf("compatibility_scope=none requires outbound_http.ssrf.mode=strict")
	}
	if err := validateSSRFRoutePolicyGuardrails(cfg, "none"); err != nil {
		return err
	}
	if cfg.OutboundHTTP.InsecureSkipVerify {
		return fmt.Errorf("compatibility_scope=none requires outbound_http.insecure_skip_verify=false")
	}
	if cfg.PeerTrust.Enabled && !cfg.PeerTrust.Policy.GlobalEnforce {
		return fmt.Errorf("compatibility_scope=none requires peer_trust.policy.global_enforce=true when peer trust is enabled")
	}
	if len(cfg.PeerProfiles.Mappings) > 0 {
		return fmt.Errorf("compatibility_scope=none forbids peer_profiles.mappings")
	}
	for name, profile := range cfg.PeerProfiles.CustomProfiles {
		if err := validateNoneScopePeerProfile(name, profile); err != nil {
			return err
		}
	}
	return nil
}

// validateNoneScopePeerProfile rejects any relaxing field in a custom peer
// profile when compatibility_scope=none is in effect.
func validateNoneScopePeerProfile(name string, p PeerProfile) error {
	if p.AllowUnsignedInbound {
		return fmt.Errorf("compatibility_scope=none forbids peer_profiles.custom_profiles.%s.allow_unsigned_inbound", name)
	}
	if p.AllowUnsignedOutbound {
		return fmt.Errorf("compatibility_scope=none forbids peer_profiles.custom_profiles.%s.allow_unsigned_outbound", name)
	}
	if p.AllowMismatchedHost {
		return fmt.Errorf("compatibility_scope=none forbids peer_profiles.custom_profiles.%s.allow_mismatched_host", name)
	}
	if p.AllowHTTP {
		return fmt.Errorf("compatibility_scope=none forbids peer_profiles.custom_profiles.%s.allow_http", name)
	}
	if p.AllowUnsignedDiscovery {
		return fmt.Errorf("compatibility_scope=none forbids peer_profiles.custom_profiles.%s.allow_unsigned_discovery", name)
	}
	if p.AcceptLegacyDiscoveryPublicKey {
		return fmt.Errorf("compatibility_scope=none forbids peer_profiles.custom_profiles.%s.accept_legacy_discovery_public_key", name)
	}
	if p.TokenExchangeGrantType != "" {
		return fmt.Errorf("compatibility_scope=none forbids peer_profiles.custom_profiles.%s.token_exchange_grant_type", name)
	}
	if len(p.TokenExchangeQuirks) > 0 {
		return fmt.Errorf("compatibility_scope=none forbids peer_profiles.custom_profiles.%s.token_exchange_quirks", name)
	}
	if len(p.AllowedBasicAuthPatterns) > 0 {
		return fmt.Errorf("compatibility_scope=none forbids peer_profiles.custom_profiles.%s.allowed_basic_auth_patterns", name)
	}
	return nil
}

func validateScopedCompatibilityScopeGuardrails(cfg *Config) error {
	if cfg.Signature.InboundMode != "strict" {
		return fmt.Errorf("compatibility_scope=scoped requires signature.inbound_mode=strict")
	}
	if cfg.Signature.OutboundMode != "strict" {
		return fmt.Errorf("compatibility_scope=scoped requires signature.outbound_mode=strict")
	}
	if cfg.Signature.PeerProfileLevelOverride == "all" {
		return fmt.Errorf("compatibility_scope=scoped requires signature.peer_profile_level_override!=all")
	}
	if cfg.Signature.OnDiscoveryError != "reject" {
		return fmt.Errorf("compatibility_scope=scoped requires signature.on_discovery_error=reject")
	}
	if cfg.Signature.AllowMismatch {
		return fmt.Errorf("compatibility_scope=scoped requires signature.allow_mismatch=false")
	}
	if cfg.TLS.Mode == "off" {
		return fmt.Errorf("compatibility_scope=scoped requires tls.mode!=off")
	}
	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		return fmt.Errorf("compatibility_scope=scoped requires outbound_http.ssrf.mode=strict")
	}
	if err := validateSSRFRoutePolicyGuardrails(cfg, "scoped"); err != nil {
		return err
	}
	if cfg.OutboundHTTP.InsecureSkipVerify {
		return fmt.Errorf("compatibility_scope=scoped requires outbound_http.insecure_skip_verify=false")
	}
	if cfg.PeerTrust.Enabled && !cfg.PeerTrust.Policy.GlobalEnforce {
		return fmt.Errorf("compatibility_scope=scoped requires peer_trust.policy.global_enforce=true when peer trust is enabled")
	}
	return nil
}

// validateSSRFRoutePolicyGuardrails enforces strict guardrails on the active
// route policy when compatibility_scope is "none" or "scoped".
func validateSSRFRoutePolicyGuardrails(cfg *Config, scope string) error {
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

	if len(policy.AllowPrivateHostSuffixes) == 0 {
		return fmt.Errorf(
			"compatibility_scope=%s: active ssrf route policy %q requires non-empty %s.allow_private_host_suffixes",
			scope, activePolicy, prefix,
		)
	}
	for _, suffix := range policy.AllowPrivateHostSuffixes {
		if strings.TrimSpace(suffix) == "" {
			return fmt.Errorf(
				"compatibility_scope=%s: active ssrf route policy %q has blank entry in %s.allow_private_host_suffixes",
				scope, activePolicy, prefix,
			)
		}
	}
	if len(policy.AllowPrivateCIDRs) == 0 {
		return fmt.Errorf(
			"compatibility_scope=%s: active ssrf route policy %q requires non-empty %s.allow_private_cidrs",
			scope, activePolicy, prefix,
		)
	}
	if len(policy.AllowedPorts) == 0 {
		return fmt.Errorf(
			"compatibility_scope=%s: active ssrf route policy %q requires non-empty %s.allowed_ports",
			scope, activePolicy, prefix,
		)
	}
	if policy.AllowIPLiterals {
		return fmt.Errorf(
			"compatibility_scope=%s: active ssrf route policy %q requires %s.allow_ip_literals=false",
			scope, activePolicy, prefix,
		)
	}
	for _, cidr := range policy.AllowPrivateCIDRs {
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			return fmt.Errorf(
				"compatibility_scope=%s: active ssrf route policy %q forbids catch-all CIDR %q in %s.allow_private_cidrs",
				scope, activePolicy, cidr, prefix,
			)
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf(
				"compatibility_scope=%s: active ssrf route policy %q has invalid CIDR %q in %s.allow_private_cidrs: %w",
				scope, activePolicy, cidr, prefix, err,
			)
		}
	}
	for _, port := range policy.AllowedPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf(
				"compatibility_scope=%s: active ssrf route policy %q has invalid port %d in %s.allowed_ports: must be in range 1-65535",
				scope, activePolicy, port, prefix,
			)
		}
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
