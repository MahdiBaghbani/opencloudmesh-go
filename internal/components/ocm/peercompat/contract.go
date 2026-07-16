// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import (
	"fmt"
	"slices"
	"sort"

	platformconfig "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

const (
	tokenQuirkAcceptPlainToken = "accept_plain_token"
	tokenQuirkSendTokenInBody  = "send_token_in_body"
)

// CompatibilityScope is the typed exception-governance axis that the matched-peer
// gate consults at decision time. It mirrors platform/config values so the gate
// can reject unknown scopes without relying on startup validation.
type CompatibilityScope string

const (
	// CompatibilityScopeScoped permits peer-scoped relaxations for named matched
	// mappings. This is the only scope under which the gate grants relaxations.
	CompatibilityScopeScoped CompatibilityScope = "scoped"
	// CompatibilityScopeNone forbids compatibility exceptions; the gate stays
	// closed even if a mapping were present.
	CompatibilityScopeNone CompatibilityScope = "none"
)

var supportedBasicAuthPatterns = map[string]struct{}{
	"token:":      {},
	"token:token": {},
	":token":      {},
	"id:token":    {},
}

// SigningCompatibility is the typed signing compatibility decision payload.
type SigningCompatibility struct {
	AllowUnsignedInbound           bool
	AllowUnsignedOutbound          bool
	AllowMismatchedHost            bool
	AllowUnsignedDiscovery         bool
	AcceptLegacyDiscoveryPublicKey bool
}

// TransportCompatibility is the typed transport compatibility decision payload.
type TransportCompatibility struct {
	AllowHTTP bool
}

// TokenExchangeCompatibility is the typed token exchange decision payload.
type TokenExchangeCompatibility struct {
	AcceptPlainToken bool
	SendTokenInBody  bool
	GrantType        string
}

// BasicAuthCompatibility is the typed Basic auth compatibility decision payload.
type BasicAuthCompatibility struct {
	AllowAllPatterns bool
	AllowedPatterns  []string
}

// CompiledProfile is the immutable, typed compatibility shape for one profile.
type CompiledProfile struct {
	Name          string
	Signing       SigningCompatibility
	Transport     TransportCompatibility
	TokenExchange TokenExchangeCompatibility
	BasicAuth     BasicAuthCompatibility
}

// ProfileSummary captures per-profile summary facts used by runtime posture.
type ProfileSummary struct {
	Name                           string
	HasRelaxations                 bool
	AllowUnsignedDiscovery         bool
	AcceptLegacyDiscoveryPublicKey bool
	AllowHTTP                      bool
	HasBasicAuthAllowlist          bool
	NonDefaultGrantType            bool
}

// CompatibilitySummary captures the compiled contract summary for runtime policy.
type CompatibilitySummary struct {
	TotalProfiles               int
	ProfilesWithRelaxations     int
	ProfilesAllowHTTP           int
	ProfilesAllowUnsignedDisc   int
	ProfilesWithBasicAllowlists int
	ProfilesWithGrantOverrides  int
	Profiles                    []ProfileSummary
}

// CompiledContract is the immutable, compiled compatibility authority.
type CompiledContract struct {
	registry *ProfileRegistry
	profiles map[string]CompiledProfile
	summary  CompatibilitySummary
	scope    CompatibilityScope
}

// NewCompiledContract builds a compiled contract from profiles and mappings.
func NewCompiledContract(
	customProfiles map[string]*Profile,
	mappings []ProfileMapping,
) (*CompiledContract, error) {
	registry := NewProfileRegistry(customProfiles, mappings)
	return BuildCompiledContractFromRegistry(registry)
}

// NewCompiledContractFromConfig builds the compiled contract from config,
// wiring the configured compatibility_scope into the compiled contract so
// the matched-peer gate enforces the operator's configured compatibility_scope.
func NewCompiledContractFromConfig(
	cfg *platformconfig.Config,
) (*CompiledContract, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}

	customProfiles := make(map[string]*Profile, len(cfg.PeerProfiles.CustomProfiles))
	for name, profileCfg := range cfg.PeerProfiles.CustomProfiles {
		customProfiles[name] = profileFromConfig(name, profileCfg)
	}

	mappings := slices.Clone(cfg.PeerProfiles.Mappings)
	registry := NewProfileRegistry(customProfiles, mappings)
	scope := compatibilityScopeFromConfig(cfg.CompatibilityScope)
	return BuildCompiledContractFromRegistryWithScope(registry, scope)
}

// compatibilityScopeFromConfig maps a raw config compatibility_scope value to
// the typed CompatibilityScope the gate consults at decision time. It
// preserves unknown raw values as-is rather than normalizing them to a known
// constant: the loader rejects unknown values at startup (see
// internal/platform/config/loader.go validateEnums), but
// scopeAllowsPeerRelaxations only grants relaxations for CompatibilityScopeScoped,
// so any value that is not exactly "scoped" (including an empty string, "none",
// or any other unrecognized value) fails closed here as a defense-in-depth
// measure independent of startup validation.
func compatibilityScopeFromConfig(raw string) CompatibilityScope {
	return CompatibilityScope(raw)
}

// BuildCompiledContractFromRegistry compiles typed compatibility decisions.
// The contract defaults to the scoped compatibility scope, so matched peers
// receive relaxations while unmatched and closed-scope peers stay strict.
func BuildCompiledContractFromRegistry(
	registry *ProfileRegistry,
) (*CompiledContract, error) {
	return BuildCompiledContractFromRegistryWithScope(registry, CompatibilityScopeScoped)
}

// BuildCompiledContractFromRegistryWithScope compiles typed compatibility
// decisions under an explicit compatibility scope. The scope is consulted by the
// matched-peer gate at decision time; only CompatibilityScopeScoped permits
// peer-scoped relaxations.
func BuildCompiledContractFromRegistryWithScope(
	registry *ProfileRegistry,
	scope CompatibilityScope,
) (*CompiledContract, error) {
	if registry == nil {
		return nil, fmt.Errorf("profile registry is nil")
	}

	names := registry.ListProfiles()
	sort.Strings(names)

	compiledProfiles := make(map[string]CompiledProfile, len(names))
	profileSummaries := make([]ProfileSummary, 0, len(names))
	for _, name := range names {
		profile := registry.GetProfileByName(name)
		if profile == nil {
			return nil, fmt.Errorf("profile %q not found in registry", name)
		}

		compiled, err := compileProfile(profile)
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		compiledProfiles[name] = compiled
		profileSummaries = append(profileSummaries, summarizeProfile(compiled))
	}

	summary := CompatibilitySummary{
		TotalProfiles: len(profileSummaries),
		Profiles:      profileSummaries,
	}
	for _, p := range profileSummaries {
		if p.HasRelaxations {
			summary.ProfilesWithRelaxations++
		}
		if p.AllowHTTP {
			summary.ProfilesAllowHTTP++
		}
		if p.AllowUnsignedDiscovery {
			summary.ProfilesAllowUnsignedDisc++
		}
		if p.HasBasicAuthAllowlist {
			summary.ProfilesWithBasicAllowlists++
		}
		if p.NonDefaultGrantType {
			summary.ProfilesWithGrantOverrides++
		}
	}

	return &CompiledContract{
		registry: registry,
		profiles: compiledProfiles,
		summary:  summary,
		scope:    scope,
	}, nil
}

// ProfileByName returns the compiled profile by name.
func (c *CompiledContract) ProfileByName(name string) (CompiledProfile, bool) {
	if c == nil {
		return CompiledProfile{}, false
	}
	profile, ok := c.profiles[name]
	if !ok {
		return CompiledProfile{}, false
	}
	return cloneCompiledProfile(profile), true
}

// ProfileForPeer returns the compiled profile for a peer domain.
func (c *CompiledContract) ProfileForPeer(peerDomain string) (CompiledProfile, bool) {
	if c == nil || c.registry == nil {
		return CompiledProfile{}, false
	}
	profile := c.registry.GetProfile(peerDomain)
	if profile == nil {
		return CompiledProfile{}, false
	}
	return c.ProfileByName(profile.Name)
}

// Summary returns the typed contract summary.
func (c *CompiledContract) Summary() CompatibilitySummary {
	if c == nil {
		return CompatibilitySummary{}
	}
	out := c.summary
	out.Profiles = slices.Clone(c.summary.Profiles)
	return out
}

// matchedPeerResult is the canonical matched-peer gate result. A zero value
// (Matched=false, zero Profile) means the gate failed closed.
type matchedPeerResult struct {
	PeerDomain string
	Profile    CompiledProfile
	Matched    bool
}

// resolveMatchedPeer is the canonical matched-peer gate. Every peer-scoped
// relaxation decision routes through it. It grants relaxations only when the
// compatibility scope is scoped and a named mapping matched the normalized
// peer domain. Empty/nil peers, nil contract or registry, any non-scoped or
// unknown scope, and unmatched peers all fail closed with Matched=false and a
// zero Profile, so callers never copy relaxation fields from a strict fallback.
func (c *CompiledContract) resolveMatchedPeer(peerInput string) matchedPeerResult {
	domain := signatureDecisionPeerDomain(peerInput)
	if domain == "" || c == nil || c.registry == nil || !c.scopeAllowsPeerRelaxations() {
		return matchedPeerResult{PeerDomain: domain}
	}

	for _, mapping := range c.registry.mappings {
		if !matchPattern(mapping.Pattern, domain) {
			continue
		}
		profile, ok := c.profiles[mapping.Profile]
		if !ok {
			return matchedPeerResult{PeerDomain: domain}
		}
		return matchedPeerResult{
			PeerDomain: domain,
			Profile:    profile,
			Matched:    true,
		}
	}

	return matchedPeerResult{PeerDomain: domain}
}

// scopeAllowsPeerRelaxations reports whether the contract scope permits
// peer-scoped relaxations. Only the scoped scope does; none and any unknown
// value fail closed at decision time without relying on startup validation.
func (c *CompiledContract) scopeAllowsPeerRelaxations() bool {
	return c != nil && c.scope == CompatibilityScopeScoped
}

func compileProfile(profile *Profile) (CompiledProfile, error) {
	grantType := profile.GetTokenExchangeGrantType()
	if grantType != "authorization_code" && grantType != "ocm_share" {
		return CompiledProfile{}, fmt.Errorf(
			"unsupported token_exchange_grant_type %q",
			grantType,
		)
	}

	tokenCompat := TokenExchangeCompatibility{GrantType: grantType}
	for _, quirk := range profile.TokenExchangeQuirks {
		switch quirk {
		case tokenQuirkAcceptPlainToken:
			tokenCompat.AcceptPlainToken = true
		case tokenQuirkSendTokenInBody:
			tokenCompat.SendTokenInBody = true
		default:
			return CompiledProfile{}, fmt.Errorf(
				"unsupported token_exchange_quirk %q",
				quirk,
			)
		}
	}

	basicAuth := BasicAuthCompatibility{
		AllowAllPatterns: len(profile.AllowedBasicAuthPatterns) == 0,
	}
	if !basicAuth.AllowAllPatterns {
		basicAuth.AllowedPatterns = make([]string, 0, len(profile.AllowedBasicAuthPatterns))
		for _, pattern := range profile.AllowedBasicAuthPatterns {
			if _, ok := supportedBasicAuthPatterns[pattern]; !ok {
				return CompiledProfile{}, fmt.Errorf(
					"unsupported allowed_basic_auth_pattern %q",
					pattern,
				)
			}
			basicAuth.AllowedPatterns = append(basicAuth.AllowedPatterns, pattern)
		}
	}

	return CompiledProfile{
		Name: profile.Name,
		Signing: SigningCompatibility{
			AllowUnsignedInbound:           profile.AllowUnsignedInbound,
			AllowUnsignedOutbound:          profile.AllowUnsignedOutbound,
			AllowMismatchedHost:            profile.AllowMismatchedHost,
			AllowUnsignedDiscovery:         profile.AllowUnsignedDiscovery,
			AcceptLegacyDiscoveryPublicKey: profile.AcceptLegacyDiscoveryPublicKey,
		},
		Transport: TransportCompatibility{
			AllowHTTP: profile.AllowHTTP,
		},
		TokenExchange: tokenCompat,
		BasicAuth:     basicAuth,
	}, nil
}

func summarizeProfile(profile CompiledProfile) ProfileSummary {
	return ProfileSummary{
		Name: profile.Name,
		HasRelaxations: profile.Signing.AllowUnsignedInbound ||
			profile.Signing.AllowUnsignedOutbound ||
			profile.Signing.AllowMismatchedHost ||
			profile.Signing.AllowUnsignedDiscovery ||
			profile.Signing.AcceptLegacyDiscoveryPublicKey ||
			profile.Transport.AllowHTTP ||
			profile.TokenExchange.AcceptPlainToken ||
			profile.TokenExchange.SendTokenInBody ||
			(len(profile.BasicAuth.AllowedPatterns) > 0) ||
			profile.TokenExchange.GrantType != "authorization_code",
		AllowUnsignedDiscovery:         profile.Signing.AllowUnsignedDiscovery,
		AcceptLegacyDiscoveryPublicKey: profile.Signing.AcceptLegacyDiscoveryPublicKey,
		AllowHTTP:                      profile.Transport.AllowHTTP,
		HasBasicAuthAllowlist:          len(profile.BasicAuth.AllowedPatterns) > 0,
		NonDefaultGrantType:            profile.TokenExchange.GrantType != "authorization_code",
	}
}

func cloneCompiledProfile(in CompiledProfile) CompiledProfile {
	out := in
	out.BasicAuth.AllowedPatterns = slices.Clone(in.BasicAuth.AllowedPatterns)
	return out
}
