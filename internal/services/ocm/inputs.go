// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ocm

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// Inputs holds dependencies for the OCM service constructor.
type Inputs struct {
	IncomingShareRepo   sharesincoming.IncomingShareRepo
	OutgoingShareRepo   sharesoutgoing.OutgoingShareRepo
	IncomingInviteRepo  invitesincoming.IncomingInviteRepo
	OutgoingInviteRepo  invitesoutgoing.OutgoingInviteRepo
	PartyRepo           identity.PartyRepo
	PolicyEngine        *peertrust.PolicyEngine
	CodeFlow            *policy.CodeFlow
	PeerMappingResolver *policy.PeerMappingResolver
	LocalIdentity       localidentity.Identity
	TokenStore          token.TokenStore
	SignatureMiddleware *inboundsignature.SignatureMiddleware
	TokenExchangePath   string
	KeyManager          *crypto.KeyManager
	// MustInviteEnforced gates inbound share creation on an exchanged invite.
	MustInviteEnforced bool
}
