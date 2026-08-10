// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package api

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// outgoingFactsResolver resolves code-flow facts for an outgoing share target.
type outgoingFactsResolver interface {
	ResolveFacts(host string) policy.Facts
}

// Inputs holds dependencies for the API service constructor.
type Inputs struct {
	PartyRepo             identity.PartyRepo
	SessionRepo           identity.SessionRepo
	UserAuth              *identity.UserAuth
	IncomingShareRepo     sharesincoming.IncomingShareRepo
	OutgoingShareRepo     sharesoutgoing.OutgoingShareRepo
	IncomingInviteRepo    invitesincoming.IncomingInviteRepo
	OutgoingInviteRepo    invitesoutgoing.OutgoingInviteRepo
	HTTPClient            *httpclient.ContextClient
	DiscoveryClient       *discovery.Client
	Signer                *crypto.RFC9421Signer
	PeerOrigin            *peerorigin.Resolver
	OutgoingFactsResolver outgoingFactsResolver
	LocalTokenEndpoint    string
	LocalIdentity         localidentity.Identity
	ContentDir            string
	Ratelimit             ratelimit.Inputs
	InterceptorProfiles   map[string]map[string]any
}
