// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import (
	"path/filepath"
	"slices"
	"strings"

	platformconfig "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// Profile represents a peer interop profile that controls how we communicate
// with a specific peer or class of peers.
type Profile struct {
	// Name is the profile identifier (e.g., "nextcloud", "owncloud", "strict")
	Name string `json:"name" toml:"name"`

	// AllowUnsignedInbound allows accepting unsigned requests from this peer
	// when in lenient mode (ignored in strict mode)
	AllowUnsignedInbound bool `json:"allow_unsigned_inbound" toml:"allow_unsigned_inbound"`

	// AllowUnsignedOutbound allows sending unsigned requests to this peer
	// when in lenient mode (ignored in strict mode)
	AllowUnsignedOutbound bool `json:"allow_unsigned_outbound" toml:"allow_unsigned_outbound"`

	// AllowMismatchedHost allows keyId host to differ from declared sender
	AllowMismatchedHost bool `json:"allow_mismatched_host" toml:"allow_mismatched_host"`

	// AllowHTTP allows HTTP (non-TLS) connections to this peer (dev-only)
	AllowHTTP bool `json:"allow_http" toml:"allow_http"`

	// AllowUnsignedDiscovery allows discovery-based signature capability checks
	// to fail open for this peer in the narrow retained call sites.
	AllowUnsignedDiscovery bool `json:"allow_unsigned_discovery" toml:"allow_unsigned_discovery"`

	// AcceptLegacyDiscoveryPublicKey allows compatibility fallback from legacy
	// discovery publicKey into canonical publicKeys for this peer.
	AcceptLegacyDiscoveryPublicKey bool `json:"accept_legacy_discovery_public_key" toml:"accept_legacy_discovery_public_key"`

	// TokenExchangeQuirks lists token exchange quirks to apply
	TokenExchangeQuirks []string `json:"token_exchange_quirks" toml:"token_exchange_quirks"`

	// TokenExchangeGrantType overrides the grant_type sent in outbound token
	// exchange requests. Empty means use spec default ("authorization_code").
	// Set to "ocm_share" for peers that expect the legacy grant type.
	TokenExchangeGrantType string `json:"token_exchange_grant_type" toml:"token_exchange_grant_type"`

	// AllowedBasicAuthPatterns whitelists specific Basic auth patterns.
	// Empty means allow all implemented patterns.
	// Patterns correspond to webdav.credentialResult.Source values with the "basic:" prefix removed:
	//   - "token:"      (from source "basic:token:")     - OCM spec: username=token, password=empty
	//   - "token:token" (from source "basic:token:token") - interop: same value twice
	//   - ":token"      (from source "basic::token")     - interop: empty username
	//   - "id:token"    (from source "basic:id:token")   - Reva/OCM-rs: provider_id:sharedSecret
	AllowedBasicAuthPatterns []string `json:"allowed_basic_auth_patterns" toml:"allowed_basic_auth_patterns"`
}

// profileFromConfig converts a config.PeerProfile into a peercompat Profile.
// It is the single bridge between the config-layer profile shape and the
// peercompat profile shape, so the compatibility fields are mapped in one
// place. Slice fields are cloned so the compiled profile never aliases config.
func profileFromConfig(name string, cfg platformconfig.PeerProfile) *Profile {
	return &Profile{
		Name:                           name,
		AllowUnsignedInbound:           cfg.AllowUnsignedInbound,
		AllowUnsignedOutbound:          cfg.AllowUnsignedOutbound,
		AllowMismatchedHost:            cfg.AllowMismatchedHost,
		AllowHTTP:                      cfg.AllowHTTP,
		AllowUnsignedDiscovery:         cfg.AllowUnsignedDiscovery,
		AcceptLegacyDiscoveryPublicKey: cfg.AcceptLegacyDiscoveryPublicKey,
		TokenExchangeQuirks:            slices.Clone(cfg.TokenExchangeQuirks),
		TokenExchangeGrantType:         cfg.TokenExchangeGrantType,
		AllowedBasicAuthPatterns:       slices.Clone(cfg.AllowedBasicAuthPatterns),
	}
}

// ProfileMapping maps a domain pattern to a profile name. It is an alias for
// config.PeerProfileMapping so the mapping shape has a single definition; the
// matched profile name is read from the Profile field.
type ProfileMapping = platformconfig.PeerProfileMapping

// ProfileRegistry manages peer interop profiles and matching.
type ProfileRegistry struct {
	profiles map[string]*Profile
	mappings []ProfileMapping
}

// NewProfileRegistry creates a registry with built-in profiles and optional custom mappings.
func NewProfileRegistry(customProfiles map[string]*Profile, mappings []ProfileMapping) *ProfileRegistry {
	reg := &ProfileRegistry{
		profiles: make(map[string]*Profile),
		mappings: mappings,
	}

	// Register built-in profiles
	for name, profile := range BuiltinProfiles() {
		reg.profiles[name] = profile
	}

	// Register custom profiles (override built-ins if same name)
	for name, profile := range customProfiles {
		reg.profiles[name] = profile
	}

	return reg
}

// GetProfile returns the profile for a peer domain.
// Returns the "strict" profile if no match is found.
func (r *ProfileRegistry) GetProfile(peerDomain string) *Profile {
	// Normalize domain (lowercase, strip port)
	domain := normalizeDomain(peerDomain)

	// Check mappings in order
	for _, mapping := range r.mappings {
		if matchPattern(mapping.Pattern, domain) {
			if profile, ok := r.profiles[mapping.Profile]; ok {
				return profile
			}
		}
	}

	// Default to strict profile
	return r.profiles["strict"]
}

// GetProfileByName returns a profile by name.
func (r *ProfileRegistry) GetProfileByName(name string) *Profile {
	if profile, ok := r.profiles[name]; ok {
		return profile
	}
	return nil
}

// ListProfiles returns all registered profile names.
func (r *ProfileRegistry) ListProfiles() []string {
	names := make([]string, 0, len(r.profiles))
	for name := range r.profiles {
		names = append(names, name)
	}
	return names
}

// BuiltinProfiles returns the default set of profiles.
func BuiltinProfiles() map[string]*Profile {
	return map[string]*Profile{
		// Strict profile: full RFC 9421 compliance expected
		"strict": {
			Name:                           "strict",
			AllowUnsignedInbound:           false,
			AllowUnsignedOutbound:          false,
			AllowMismatchedHost:            false,
			AllowHTTP:                      false,
			AllowUnsignedDiscovery:         false,
			AcceptLegacyDiscoveryPublicKey: false,
			TokenExchangeQuirks:            nil,
			AllowedBasicAuthPatterns:       nil, // allow all patterns
		},

		// Nextcloud profile: common Nextcloud interop quirks
		"nextcloud": {
			Name:                           "nextcloud",
			AllowUnsignedInbound:           true, // Nextcloud may not sign requests
			AllowUnsignedOutbound:          true, // May need to send unsigned for compat
			AllowMismatchedHost:            true, // Nextcloud keyId may not match sender
			AllowHTTP:                      false,
			AllowUnsignedDiscovery:         false,
			AcceptLegacyDiscoveryPublicKey: true,        // Older peers may still use publicKey
			TokenExchangeGrantType:         "ocm_share", // Nextcloud expects legacy grant type
			TokenExchangeQuirks: []string{
				"accept_plain_token", // Accept token in request body
				"send_token_in_body", // Send token in request body
			},
			AllowedBasicAuthPatterns: nil, // allow all patterns
		},

		// ownCloud profile: similar to Nextcloud with minor differences
		"owncloud": {
			Name:                           "owncloud",
			AllowUnsignedInbound:           true,
			AllowUnsignedOutbound:          true,
			AllowMismatchedHost:            true,
			AllowHTTP:                      false,
			AllowUnsignedDiscovery:         false,
			AcceptLegacyDiscoveryPublicKey: true,
			TokenExchangeGrantType:         "ocm_share", // ownCloud expects legacy grant type
			TokenExchangeQuirks: []string{
				"accept_plain_token",
				"send_token_in_body",
			},
			AllowedBasicAuthPatterns: nil, // allow all patterns
		},

		// Dev profile: allows everything for local testing
		"dev": {
			Name:                           "dev",
			AllowUnsignedInbound:           true,
			AllowUnsignedOutbound:          true,
			AllowMismatchedHost:            true,
			AllowHTTP:                      true, // Allow HTTP for local dev
			AllowUnsignedDiscovery:         false,
			AcceptLegacyDiscoveryPublicKey: true,
			TokenExchangeQuirks: []string{
				"accept_plain_token",
				"send_token_in_body",
			},
			AllowedBasicAuthPatterns: nil, // allow all patterns
		},
	}
}

// normalizeDomain normalizes a domain for matching.
func normalizeDomain(domain string) string {
	// Lowercase
	domain = strings.ToLower(domain)

	// Strip port if present
	if idx := strings.LastIndex(domain, ":"); idx > 0 {
		// Check it's not an IPv6 address part
		if !strings.Contains(domain[idx:], "]") {
			domain = domain[:idx]
		}
	}

	// Strip trailing dot
	domain = strings.TrimSuffix(domain, ".")

	return domain
}

// matchPattern checks if a domain matches a pattern.
// Patterns can be:
// - Exact match: "example.com"
// - Wildcard suffix: "*.example.com" (matches any subdomain)
// - Wildcard prefix: "cloud.*" (matches cloud.anything)
func matchPattern(pattern, domain string) bool {
	pattern = strings.ToLower(pattern)
	domain = strings.ToLower(domain)

	// Exact match
	if pattern == domain {
		return true
	}

	// Glob pattern matching using filepath.Match
	// Note: filepath.Match handles * as single-segment wildcard
	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, domain)
		if matched {
			return true
		}

		// Special case: "*.example.com" should match "sub.example.com"
		// but not "example.com" itself
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			if strings.HasSuffix(domain, suffix) && len(domain) > len(suffix) {
				return true
			}
		}
	}

	return false
}

// GetTokenExchangeGrantType returns the grant_type to use for outbound token
// exchange requests to this peer. Returns "authorization_code" (spec default)
// when the profile does not override it.
func (p *Profile) GetTokenExchangeGrantType() string {
	if p.TokenExchangeGrantType != "" {
		return p.TokenExchangeGrantType
	}
	return "authorization_code"
}

// HasQuirk checks if a profile has a specific quirk enabled.
func (p *Profile) HasQuirk(quirk string) bool {
	for _, q := range p.TokenExchangeQuirks {
		if q == quirk {
			return true
		}
	}
	return false
}

// IsBasicAuthPatternAllowed checks if a Basic auth pattern is allowed by this profile.
// Returns true if the pattern is in AllowedBasicAuthPatterns or if the list is empty
// (empty means allow all implemented patterns).
func (p *Profile) IsBasicAuthPatternAllowed(pattern string) bool {
	if len(p.AllowedBasicAuthPatterns) == 0 {
		return true // empty means allow all
	}
	for _, allowed := range p.AllowedBasicAuthPatterns {
		if allowed == pattern {
			return true
		}
	}
	return false
}
