// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outboundsigning

import (
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
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
	OutboundMode           string
	PeerProfileOverride    string
	ProfileRegistry        *peercompat.ProfileRegistry
}

func NewOutboundPolicy(cfg *config.Config, registry *peercompat.ProfileRegistry) *OutboundPolicy {
	return &OutboundPolicy{
		OutboundMode:        cfg.Signature.OutboundMode,
		PeerProfileOverride: cfg.Signature.PeerProfileLevelOverride,
		ProfileRegistry:     registry,
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

	if kind == EndpointTokenExchange {
		return p.decideTokenExchange(profile, hasSigner)
	}

	switch p.OutboundMode {
	case "strict":
		return p.decideStrict(kind, disc, profile, hasSigner)
	case "token-only":
		return SigningDecision{
			ShouldSign: false,
			Reason:     "outbound_mode=token-only does not sign " + string(kind),
		}
	case "criteria-only":
		return p.decideCriteriaOnly(kind, disc, profile, hasSigner)
	default:
		return SigningDecision{
			ShouldSign: false,
			Reason:     "unknown outbound_mode: " + p.OutboundMode,
			Error:      fmt.Errorf("unknown outbound_mode: %s", p.OutboundMode),
		}
	}
}

func (p *OutboundPolicy) decideTokenExchange(profile *peercompat.Profile, hasSigner bool) SigningDecision {
	if profile != nil && profile.HasQuirk("accept_plain_token") {
		if p.canApplyRelaxation("outbound") {
			return SigningDecision{
				ShouldSign: false,
				Reason:     "peer profile allows unsigned token exchange (accept_plain_token quirk)",
			}
		}
	}
	if !hasSigner {
		return SigningDecision{
			ShouldSign: true,
			Reason:     "token exchange requires signature",
			Error:      fmt.Errorf("outbound_mode requires signing token exchange but no signer available"),
		}
	}

	return SigningDecision{
		ShouldSign: true,
		Reason:     "token exchange signed per outbound_mode",
	}
}

// decideStrict handles strict mode signing decisions.
func (p *OutboundPolicy) decideStrict(
	kind EndpointKind,
	disc *discovery.Discovery,
	profile *peercompat.Profile,
	hasSigner bool,
) SigningDecision {
	if profile != nil && profile.AllowUnsignedOutbound {
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
	kind EndpointKind,
	disc *discovery.Discovery,
	profile *peercompat.Profile,
	hasSigner bool,
) SigningDecision {
	if disc == nil {
		return SigningDecision{
			ShouldSign: false,
			Reason:     "no discovery document available",
		}
	}
	peerRequiresSignatures := disc.HasCriteria("http-request-signatures")

	if !peerRequiresSignatures {
		if profile != nil && profile.AllowUnsignedOutbound && p.canApplyRelaxation("outbound") {
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
