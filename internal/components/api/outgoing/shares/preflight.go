// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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
// IncludesTokenExchangeRequirement policy. See IETF-OCM.md at 6a0586183cbef10ecae9dedc42561806447eb2f5, Share Creation Notification
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
