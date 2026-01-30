// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package federation

import (
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// EndpointKind represents the type of outbound OCM endpoint.
type EndpointKind string

const (
	EndpointShares        EndpointKind = "shares"
	EndpointNotifications EndpointKind = "notifications"
	EndpointInvites       EndpointKind = "invites"
	EndpointTokenExchange EndpointKind = "token-exchange"
)

// SigningDecision represents the result of an outbound signing policy check.
type SigningDecision struct {
	ShouldSign bool
	Reason     string
	Error      error // Non-nil when signing is required but not possible
}

// OutboundPolicy encapsulates the outbound signing policy configuration.
type OutboundPolicy struct {
	OutboundMode           string
	PeerProfileOverride    string
	ProfileRegistry        *peercompat.ProfileRegistry
}

// NewOutboundPolicy creates an OutboundPolicy from config.
func NewOutboundPolicy(cfg *config.Config, registry *peercompat.ProfileRegistry) *OutboundPolicy {
	return &OutboundPolicy{
		OutboundMode:        cfg.Signature.OutboundMode,
		PeerProfileOverride: cfg.Signature.PeerProfileLevelOverride,
		ProfileRegistry:     registry,
	}
}

// ShouldSign determines whether an outbound request should be signed.
// Returns a decision with reason, and error if signing is required but impossible.
func (p *OutboundPolicy) ShouldSign(
	kind EndpointKind,
	peerDomain string,
	disc *discovery.Discovery,
	hasSigner bool,
) SigningDecision {
	// outbound_mode=off: never sign anything
	if p.OutboundMode == "off" {
		return SigningDecision{
			ShouldSign: false,
			Reason:     "outbound_mode=off",
		}
	}

	// Get peer profile
	var profile *peercompat.Profile
	if p.ProfileRegistry != nil {
		profile = p.ProfileRegistry.GetProfile(peerDomain)
	}

	// Token exchange always signs unless outbound_mode=off
	if kind == EndpointTokenExchange {
		return p.decideTokenExchange(profile, hasSigner)
	}

	// For shares/notifications/invites, apply mode-specific logic
	switch p.OutboundMode {
	case "strict":
		return p.decideStrict(kind, disc, profile, hasSigner)
	case "token-only":
		// token-only: don't sign shares/notifications/invites
		return SigningDecision{
			ShouldSign: false,
			Reason:     "outbound_mode=token-only does not sign " + string(kind),
		}
	case "criteria-only":
		return p.decideCriteriaOnly(kind, disc, profile, hasSigner)
	default:
		// Unknown mode, fail closed
		return SigningDecision{
			ShouldSign: false,
			Reason:     "unknown outbound_mode: " + p.OutboundMode,
			Error:      fmt.Errorf("unknown outbound_mode: %s", p.OutboundMode),
		}
	}
}

// decideTokenExchange handles token exchange signing decisions.
func (p *OutboundPolicy) decideTokenExchange(profile *peercompat.Profile, hasSigner bool) SigningDecision {
	// Check if peer profile allows unsigned token exchange
	if profile != nil && profile.HasQuirk("accept_plain_token") {
		if p.canApplyRelaxation("outbound") {
			return SigningDecision{
				ShouldSign: false,
				Reason:     "peer profile allows unsigned token exchange (accept_plain_token quirk)",
			}
		}
	}

	// Default: sign token exchange
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
	// Check if peer profile allows unsigned outbound in strict mode
	if profile != nil && profile.AllowUnsignedOutbound {
		if p.PeerProfileOverride == "all" {
			// Guardrail: cannot skip signing if peer requires signatures via criteria
			peerRequiresSignatures := disc != nil && disc.HasCriteria("http-request-signatures")
			if peerRequiresSignatures {
				// Peer declared they require signatures - must sign despite profile
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
			// Peer does not require signatures - allow unsigned per profile
			return SigningDecision{
				ShouldSign: false,
				Reason:     "peer profile allows unsigned outbound with peer_profile_level_override=all",
			}
		}
	}

	// In strict mode, we attempt to sign all requests
	if !hasSigner {
		return SigningDecision{
			ShouldSign: true,
			Reason:     "strict mode requires signing",
			Error:      fmt.Errorf("outbound_mode=strict requires signing but no signer available"),
		}
	}

	// Check if peer can receive signed requests
	if disc != nil && (!disc.HasCapability("http-sig") || len(disc.PublicKeys) == 0) {
		// Strict mode still signs even if peer doesn't advertise support
		// The peer may still accept signatures
	}

	return SigningDecision{
		ShouldSign: true,
		Reason:     "strict mode: always sign",
	}
}

// decideCriteriaOnly handles criteria-only mode signing decisions.
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

	// Check if peer requires signatures via criteria
	peerRequiresSignatures := disc.HasCriteria("http-request-signatures")

	if !peerRequiresSignatures {
		// Check peer profile for relaxation
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

	// Peer requires signatures - verify they have the capability to receive them
	if !disc.HasCapability("http-sig") || len(disc.PublicKeys) == 0 {
		return SigningDecision{
			ShouldSign: true,
			Reason:     "peer requires signatures but lacks http-sig capability or publicKeys",
			Error:      fmt.Errorf("peer requires http-request-signatures but does not advertise http-sig capability or publicKeys"),
		}
	}

	// Peer requires and supports signatures
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

// canApplyRelaxation checks if peer profile relaxations are allowed.
func (p *OutboundPolicy) canApplyRelaxation(direction string) bool {
	switch p.PeerProfileOverride {
	case "off":
		return false
	case "all":
		return true
	case "non-strict":
		// Check if the relevant mode is not strict
		if direction == "outbound" {
			return p.OutboundMode != "strict"
		}
		return true
	default:
		return false
	}
}
