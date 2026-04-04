// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outboundsigning

import (
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
)

type EndpointKind string

const (
	EndpointShares        EndpointKind = "shares"
	EndpointNotifications EndpointKind = "notifications"
	EndpointInvites       EndpointKind = "invites"
	EndpointTokenExchange EndpointKind = "token-exchange"
)

type SigningDecision struct {
	ShouldSign bool
	Reason     string
	Error      error // Non-nil when signing is required but not possible
}

type OutboundPolicy struct {
	OutboundMode        string
	PeerProfileOverride string
	OnDiscoveryError    string
	ProfileRegistry     *peercompat.ProfileRegistry
	PeerContract        *peercompat.CompiledContract
	runtimePolicy       *policy.RuntimePolicy
	canonicalPolicy     *policy.OpenCloudMeshPolicy
}

func NewOutboundPolicy(
	runtimePolicy *policy.RuntimePolicy,
	registry *peercompat.ProfileRegistry,
	peerContract *peercompat.CompiledContract,
	canonicalPolicy *policy.OpenCloudMeshPolicy,
) *OutboundPolicy {
	outboundMode := "off"
	peerProfileOverride := "off"
	onDiscoveryError := "reject"
	if runtimePolicy != nil {
		signature := runtimePolicy.Evaluate().Signature
		if signature.OutboundMode != "" {
			outboundMode = signature.OutboundMode
		}
		if signature.PeerProfileLevelOverride != "" {
			peerProfileOverride = signature.PeerProfileLevelOverride
		}
		if signature.OnDiscoveryError != "" {
			onDiscoveryError = signature.OnDiscoveryError
		}
	}
	return &OutboundPolicy{
		OutboundMode:        outboundMode,
		PeerProfileOverride: peerProfileOverride,
		OnDiscoveryError:    onDiscoveryError,
		ProfileRegistry:     registry,
		PeerContract:        peerContract,
		runtimePolicy:       runtimePolicy,
		canonicalPolicy:     canonicalPolicy,
	}
}

// ShouldSign returns whether to sign; error when signing required but impossible.
func (p *OutboundPolicy) ShouldSign(
	kind EndpointKind,
	peerDomain string,
	disc *discovery.Discovery,
	hasSigner bool,
) SigningDecision {
	if p.OutboundMode == "off" {
		return SigningDecision{
			ShouldSign: false,
			Reason:     "outbound_mode=off",
		}
	}

	var profile *peercompat.Profile
	if p.ProfileRegistry != nil {
		profile = p.ProfileRegistry.GetProfile(peerDomain)
	}
	peerDecision := p.signatureDecision(peerDomain)

	if kind == EndpointTokenExchange {
		return p.decideTokenExchange(disc, profile, hasSigner)
	}

	switch p.OutboundMode {
	case "strict":
		return p.decideStrict(disc, peerDecision, hasSigner)
	case "token-only":
		return SigningDecision{
			ShouldSign: false,
			Reason:     "outbound_mode=token-only does not sign " + string(kind),
		}
	case "criteria-only":
		return p.decideCriteriaOnly(peerDomain, disc, peerDecision, hasSigner)
	default:
		return SigningDecision{
			ShouldSign: false,
			Reason:     "unknown outbound_mode: " + p.OutboundMode,
			Error:      fmt.Errorf("unknown outbound_mode: %s", p.OutboundMode),
		}
	}
}

func (p *OutboundPolicy) decideTokenExchange(disc *discovery.Discovery, profile *peercompat.Profile, hasSigner bool) SigningDecision {
	localPolicy := "legacy"
	if p.canonicalPolicy != nil {
		ev := p.canonicalPolicy.Evaluate()
		if ev.PeerPolicy != "" {
			localPolicy = ev.PeerPolicy
		}
	}

	if disc != nil {
		peerIsStrict := disc.HasCriteria("token-exchange")
		peerHasExchangeToken := disc.HasCapability("exchange-token")

		if peerIsStrict {
			if !hasSigner {
				return SigningDecision{
					ShouldSign: true,
					Reason:     "strict peer requires signed token exchange",
					Error:      fmt.Errorf("strict peer requires signed token exchange but no signer available"),
				}
			}
			return SigningDecision{
				ShouldSign: true,
				Reason:     "strict peer requires signed token exchange",
			}
		}

		if !peerHasExchangeToken {
			return SigningDecision{
				ShouldSign: false,
				Reason:     "peer does not advertise exchange-token capability",
			}
		}

		if localPolicy == "strict" {
			if !hasSigner {
				return SigningDecision{
					ShouldSign: true,
					Reason:     "strict policy requires signed token exchange",
					Error:      fmt.Errorf("strict policy requires signed token exchange but no signer available"),
				}
			}
			return SigningDecision{
				ShouldSign: true,
				Reason:     "strict policy requires signed token exchange",
			}
		}
	}

	if profile != nil && profile.HasQuirk("accept_plain_token") && localPolicy == "legacy" {
		if p.canApplyRelaxation("outbound") {
			return SigningDecision{
				ShouldSign: false,
				Reason:     "peer profile allows unsigned token exchange (accept_plain_token quirk)",
			}
		}
	}
	if !hasSigner {
		if localPolicy == "legacy" {
			return SigningDecision{
				ShouldSign: false,
				Reason:     "legacy policy allows unsigned token exchange when signer is unavailable",
			}
		}
		return SigningDecision{
			ShouldSign: true,
			Reason:     "token exchange requires signature",
			Error:      fmt.Errorf("outbound_mode requires signing token exchange but no signer available"),
		}
	}

	return SigningDecision{
		ShouldSign: true,
		Reason:     "token exchange signed per outbound policy",
	}
}

// decideStrict handles strict mode signing decisions.
func (p *OutboundPolicy) decideStrict(
	disc *discovery.Discovery,
	peerDecision peercompat.SignaturePeerDecision,
	hasSigner bool,
) SigningDecision {
	if peerDecision.Matched && peerDecision.AllowUnsignedOutbound {
		if p.PeerProfileOverride == "all" {
			peerRequiresSignatures := disc != nil && disc.HasCriteria("http-request-signatures")
			if peerRequiresSignatures {
				if !hasSigner {
					return SigningDecision{
						ShouldSign: true,
						Reason:     "peer requires signatures (criteria) but no signer available",
						Error:      fmt.Errorf("peer requires http-request-signatures but no signer available"),
					}
				}
				return SigningDecision{
					ShouldSign: true,
					Reason:     "peer requires signatures (criteria overrides profile relaxation)",
				}
			}
			return SigningDecision{
				ShouldSign: false,
				Reason:     "peer profile allows unsigned outbound with peer_profile_level_override=all",
			}
		}
	}
	if !hasSigner {
		return SigningDecision{
			ShouldSign: true,
			Reason:     "strict mode requires signing",
			Error:      fmt.Errorf("outbound_mode=strict requires signing but no signer available"),
		}
	}
	return SigningDecision{
		ShouldSign: true,
		Reason:     "strict mode: always sign",
	}
}

func (p *OutboundPolicy) decideCriteriaOnly(
	peerDomain string,
	disc *discovery.Discovery,
	peerDecision peercompat.SignaturePeerDecision,
	hasSigner bool,
) SigningDecision {
	if disc == nil {
		discoveryDecision := p.resolveDiscoveryFailure(peerDomain)
		if !discoveryDecision.Allow {
			return SigningDecision{
				ShouldSign: true,
				Reason:     "discovery unavailable and resolved decision=reject",
				Error:      fmt.Errorf("peer discovery unavailable for criteria-only outbound signing decision"),
			}
		}
		return SigningDecision{
			ShouldSign: false,
			Reason:     "discovery unavailable and resolved decision=allow",
		}
	}
	peerRequiresSignatures := disc.HasCriteria("http-request-signatures")

	if !peerRequiresSignatures {
		if peerDecision.Matched && peerDecision.AllowUnsignedOutbound && p.canApplyRelaxation("outbound") {
			return SigningDecision{
				ShouldSign: false,
				Reason:     "peer does not require signatures and profile allows unsigned",
			}
		}
		return SigningDecision{
			ShouldSign: false,
			Reason:     "peer criteria does not include http-request-signatures",
		}
	}
	if !disc.HasCapability("http-sig") || len(disc.PublicKeys) == 0 {
		return SigningDecision{
			ShouldSign: true,
			Reason:     "peer requires signatures but lacks http-sig capability or publicKeys",
			Error:      fmt.Errorf("peer requires http-request-signatures but does not advertise http-sig capability or publicKeys"),
		}
	}
	if !hasSigner {
		return SigningDecision{
			ShouldSign: true,
			Reason:     "peer requires signatures",
			Error:      fmt.Errorf("peer requires http-request-signatures but no signer available"),
		}
	}

	return SigningDecision{
		ShouldSign: true,
		Reason:     "peer criteria includes http-request-signatures",
	}
}

func (p *OutboundPolicy) signatureDecision(peerDomain string) peercompat.SignaturePeerDecision {
	if p.PeerContract != nil {
		return p.PeerContract.SignatureDecisionForPeer(peerDomain)
	}

	decision := peercompat.SignaturePeerDecision{
		PeerDomain: peerDomain,
		Profile:    "strict",
	}
	if p.ProfileRegistry == nil {
		return decision
	}
	profile := p.ProfileRegistry.GetProfile(peerDomain)
	if profile == nil {
		return decision
	}
	decision.Profile = profile.Name
	decision.Matched = profile.Name != "strict"
	decision.AllowUnsignedInbound = profile.AllowUnsignedInbound
	decision.AllowUnsignedOutbound = profile.AllowUnsignedOutbound
	decision.AllowMismatchedHost = profile.AllowMismatchedHost
	decision.AllowUnsignedDiscovery = profile.AllowUnsignedDiscovery
	return decision
}

func (p *OutboundPolicy) resolveDiscoveryFailure(peerDomain string) peercompat.DiscoveryFailureDecision {
	if p.PeerContract != nil {
		return p.PeerContract.ResolveDiscoveryFailure(peerDomain, p.OnDiscoveryError)
	}

	if p.OnDiscoveryError == "allow" {
		return peercompat.DiscoveryFailureDecision{
			PeerDomain: peerDomain,
			Allow:      true,
			ReasonCode: "global_on_discovery_error_allow",
		}
	}

	return peercompat.DiscoveryFailureDecision{
		PeerDomain: peerDomain,
		Allow:      false,
		ReasonCode: "discovery_error_reject",
	}
}

func (p *OutboundPolicy) canApplyRelaxation(direction string) bool {
	switch p.PeerProfileOverride {
	case "off":
		return false
	case "all":
		return true
	case "non-strict":
		if direction == "outbound" {
			return p.OutboundMode != "strict"
		}
		return true
	default:
		return false
	}
}
