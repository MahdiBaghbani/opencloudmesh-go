// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package resolve

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// ResolveInputs bundles the cross-cutting values discovery resolution needs.
// Wiring assembles this struct; resolve does not read the global deps bag.
type ResolveInputs struct {
	LocalIdentity     localidentity.Identity
	RouteOpts         service.RouteOpts
	TokenExchangePath string
	KeyManager        *crypto.KeyManager
	CodeFlow          *policy.CodeFlow
	// Resolver is the scope-gated peer-mapping resolver that drives discovery
	// criteria and capabilities. When nil, Resolve falls back to CodeFlow.Evaluate.
	Resolver *policy.PeerMappingResolver
	// JwksURIOverride is the configured signature.jwks_uri override. Empty
	// means derive the advertised jwksUri from the route-inventory projection
	// (the GET /jwks route's DiscoveryFields projection), not a fixed path.
	JwksURIOverride string

	// AdvertiseDenylist and AdvertiseAllowlist reflect peer_trust policy lists
	// wired by the caller. The caller sets these only when peer_trust.enabled is
	// true and the corresponding list is nonempty; otherwise both stay false.
	AdvertiseDenylist  bool
	AdvertiseAllowlist bool

	// AdvertiseMustInvite reflects must-invite enforcement wired by the caller.
	// Enforcement is on by default; an explicit opt-out clears this flag.
	AdvertiseMustInvite bool

	// AdvertiseNotifications reflects whether the local notifications handler is wired.
	AdvertiseNotifications bool
}
