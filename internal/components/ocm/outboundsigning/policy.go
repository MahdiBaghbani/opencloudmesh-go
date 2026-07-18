// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outboundsigning

import (
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
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
	OutboundMode string
	// StrictNone is true for strict outbound mode with peer_profile_level_override=off
	// (compatibility_scope=none). All endpoint kinds sign uniformly in this lane.
	StrictNone   bool
	PeerContract *peercompat.CompiledContract
}

type ResolvedInputs struct {
	OutboundMode        string
	PeerProfileOverride string
}

// ResolveInputs returns the fixed outbound signing inputs for the local code
// flow: strict outbound mode with peer-profile overrides off.
func ResolveInputs() ResolvedInputs {
	return ResolvedInputs{
		OutboundMode:        "strict",
		PeerProfileOverride: "off",
	}
}

func NewOutboundPolicy(
	inputs ResolvedInputs,
	peerContract *peercompat.CompiledContract,
) *OutboundPolicy {
	return &OutboundPolicy{
		OutboundMode: inputs.OutboundMode,
		StrictNone: inputs.OutboundMode == "strict" &&
			inputs.PeerProfileOverride == "off",
		PeerContract: peerContract,
	}
}

// ShouldSign returns whether to sign; error when signing required but impossible.
func (p *OutboundPolicy) ShouldSign(
	kind EndpointKind,
	peerDomain string,
	disc *discovery.Discovery,
	hasSigner bool,
) SigningDecision {
	if kind == EndpointTokenExchange && !p.StrictNone {
		return p.decideTokenExchange(peerDomain, disc, hasSigner)
	}

	if p.OutboundMode != "strict" {
		return SigningDecision{
			ShouldSign: false,
			Reason:     "unknown outbound_mode: " + p.OutboundMode,
			Error:      fmt.Errorf("unknown outbound_mode: %s", p.OutboundMode),
		}
	}
	return p.decideStrict(peerDomain, disc, hasSigner)
}

func (p *OutboundPolicy) decideTokenExchange(peerDomain string, disc *discovery.Discovery, hasSigner bool) SigningDecision {
	if disc != nil {
		if disc.HasCriteria(spec.CriteriaMustExchangeToken) {
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

		if !disc.HasCapability("exchange-token") {
			return SigningDecision{
				ShouldSign: false,
				Reason:     "peer does not advertise exchange-token capability",
			}
		}
	}

	if !hasSigner {
		return SigningDecision{
			ShouldSign: true,
			Reason:     "token exchange requires signature",
			Error:      fmt.Errorf("token exchange requires signing but no signer available"),
		}
	}

	return SigningDecision{
		ShouldSign: true,
		Reason:     "token exchange is always signed",
	}
}

// TokenExchangeDecisionForPeer returns compiled token compatibility decisions
// for the peer. Without a compiled contract, strict defaults are returned.
func (p *OutboundPolicy) TokenExchangeDecisionForPeer(peerDomain string) peercompat.TokenExchangeDecision {
	if p == nil || p.PeerContract == nil {
		return peercompat.TokenExchangeDecision{
			PeerDomain: peerDomain,
			Profile:    "strict",
			GrantType:  "authorization_code",
		}
	}
	return p.PeerContract.TokenExchangeDecisionForPeer(peerDomain)
}

// TokenExchangeFallbackForReason returns typed retry permissions keyed by
// classified failure reason.
func (p *OutboundPolicy) TokenExchangeFallbackForReason(peerDomain, reasonCode string) peercompat.TokenExchangeFallbackDecision {
	if p == nil || p.PeerContract == nil {
		return peercompat.TokenExchangeFallbackDecision{
			PeerDomain: peerDomain,
			Profile:    "strict",
			ReasonCode: reasonCode,
		}
	}
	return p.PeerContract.TokenExchangeFallbackForReason(peerDomain, reasonCode)
}

func (p *OutboundPolicy) decideStrict(
	peerDomain string,
	disc *discovery.Discovery,
	hasSigner bool,
) SigningDecision {
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
