// Package shares provides the session-gated handler for POST /api/shares/outgoing.
package shares

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// mustIncludeTokenExchange reports whether the outbound WebDAV protocol must
// include the must-exchange-token requirement.
//
// It is true when the receiver advertises the must-exchange-token discovery
// criterion or when the local code-flow facts include the token-exchange
// requirement.
//
// Facts.RequiresTokenExchange is intentionally not consulted here: it governs
// the local receiver's inbound admission policy and discovery criteria, while
// outbound inclusion is driven by the peer's advertised criteria and the local
// IncludesTokenExchangeRequirement policy. See IETF-OCM.md at a5b5da6, Share Creation Notification
// section, "Before constructing the notification...".
func mustIncludeTokenExchange(facts policy.Facts, disc *spec.Discovery) bool {
	peerForced := disc != nil && disc.HasCriteria(spec.CriteriaMustExchangeToken)
	return peerForced || facts.IncludesTokenExchangeRequirement
}

// tokenExchangeRequirements returns the WebDAV requirements slice for the given
// inclusion decision.
func tokenExchangeRequirements(mustInclude bool) []string {
	if mustInclude {
		return []string{spec.RequirementMustExchangeToken}
	}

	return nil
}
