// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package configfixture

import "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"

// CodeFlowLegacyVoluntary returns a code-flow policy that relaxes only the
// includes-token-exchange requirement while keeping the other relaxable
// knobs enforced.
func CodeFlowLegacyVoluntary() *policy.CodeFlow {
	includesFalse := false
	requiresTrue := true
	httpSigTrue := true

	return &policy.CodeFlow{
		IncludesTokenExchangeRequirement: &includesFalse,
		RequiresTokenExchangeRequirement: &requiresTrue,
		RequiresHTTPRequestSignatures:    &httpSigTrue,
	}
}
