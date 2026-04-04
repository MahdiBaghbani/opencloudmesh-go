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

var supportedBasicAuthPatterns = map[string]struct{}{
	"token:":      {},
	"token:token": {},
	":token":      {},
	"id:token":    {},
}

// SigningCompatibility is the typed signing compatibility decision payload.
type SigningCompatibility struct {
	AllowUnsignedInbound   bool
	AllowUnsignedOutbound  bool
	AllowMismatchedHost    bool
	AllowUnsignedDiscovery bool
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
	Name                   string
	HasRelaxations         bool
	AllowUnsignedDiscovery bool
	AllowHTTP              bool
	HasBasicAuthAllowlist  bool
	NonDefaultGrantType    bool
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
}

// NewCompiledContract builds a compiled contract from profiles and mappings.
func NewCompiledContract(
	customProfiles map[string]*Profile,
	mappings []ProfileMapping,
) (*CompiledContract, error) {
	registry := NewProfileRegistry(customProfiles, mappings)
	return BuildCompiledContractFromRegistry(registry)
}

// NewCompiledContractFromConfig builds the compiled contract from config.
func NewCompiledContractFromConfig(
	cfg *platformconfig.Config,
) (*CompiledContract, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}

	customProfiles := make(map[string]*Profile, len(cfg.PeerProfiles.CustomProfiles))
	for name, profileCfg := range cfg.PeerProfiles.CustomProfiles {
		customProfiles[name] = &Profile{
			Name:                     name,
			AllowUnsignedInbound:     profileCfg.AllowUnsignedInbound,
			AllowUnsignedOutbound:    profileCfg.AllowUnsignedOutbound,
			AllowMismatchedHost:      profileCfg.AllowMismatchedHost,
			AllowHTTP:                profileCfg.AllowHTTP,
			AllowUnsignedDiscovery:   profileCfg.AllowUnsignedDiscovery,
			TokenExchangeQuirks:      slices.Clone(profileCfg.TokenExchangeQuirks),
			TokenExchangeGrantType:   profileCfg.TokenExchangeGrantType,
			AllowedBasicAuthPatterns: slices.Clone(profileCfg.AllowedBasicAuthPatterns),
		}
	}

	mappings := make([]ProfileMapping, len(cfg.PeerProfiles.Mappings))
	for idx, mapping := range cfg.PeerProfiles.Mappings {
		mappings[idx] = ProfileMapping{
			Pattern:     mapping.Pattern,
			ProfileName: mapping.Profile,
		}
	}

	return NewCompiledContract(customProfiles, mappings)
}

// BuildCompiledContractFromRegistry compiles typed compatibility decisions.
func BuildCompiledContractFromRegistry(
	registry *ProfileRegistry,
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
	}, nil
}

// ProfileRegistry returns the underlying profile registry for transitional paths.
func (c *CompiledContract) ProfileRegistry() *ProfileRegistry {
	if c == nil {
		return nil
	}
	return c.registry
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
			AllowUnsignedInbound:   profile.AllowUnsignedInbound,
			AllowUnsignedOutbound:  profile.AllowUnsignedOutbound,
			AllowMismatchedHost:    profile.AllowMismatchedHost,
			AllowUnsignedDiscovery: profile.AllowUnsignedDiscovery,
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
			profile.Transport.AllowHTTP ||
			profile.TokenExchange.AcceptPlainToken ||
			profile.TokenExchange.SendTokenInBody ||
			(len(profile.BasicAuth.AllowedPatterns) > 0) ||
			profile.TokenExchange.GrantType != "authorization_code",
		AllowUnsignedDiscovery: profile.Signing.AllowUnsignedDiscovery,
		AllowHTTP:              profile.Transport.AllowHTTP,
		HasBasicAuthAllowlist:  len(profile.BasicAuth.AllowedPatterns) > 0,
		NonDefaultGrantType:    profile.TokenExchange.GrantType != "authorization_code",
	}
}

func cloneCompiledProfile(in CompiledProfile) CompiledProfile {
	out := in
	out.BasicAuth.AllowedPatterns = slices.Clone(in.BasicAuth.AllowedPatterns)
	return out
}
