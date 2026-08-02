// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// Deps holds shared dependencies built by wiring.Build for service construction.
type Deps struct {
	// Identity (for session-gated endpoints)
	PartyRepo   identity.PartyRepo
	SessionRepo identity.SessionRepo
	UserAuth    *identity.UserAuth

	// Repos
	IncomingShareRepo  sharesincoming.IncomingShareRepo
	OutgoingShareRepo  sharesoutgoing.OutgoingShareRepo
	OutgoingInviteRepo invitesoutgoing.OutgoingInviteRepo
	IncomingInviteRepo invitesincoming.IncomingInviteRepo
	TokenStore         token.TokenStore

	// Clients
	HTTPClient      *httpclient.ContextClient
	DiscoveryClient *discovery.Client

	// CodeFlow is a fixed-true product profile with no config knobs,
	// constructed by policy.NewCodeFlow().
	CodeFlow *policy.CodeFlow

	// Crypto
	KeyManager          *crypto.KeyManager
	Signer              *crypto.RFC9421Signer
	SignatureMiddleware *signature.SignatureMiddleware

	// Peer trust (optional)
	TrustGroupMgr *peertrust.TrustGroupManager
	PolicyEngine  *peertrust.PolicyEngine
	PeerOrigin    *peerorigin.Resolver

	// LocalIdentity is the SSOT for published public identity derived at startup.
	LocalIdentity localidentity.Identity

	// Config (for handlers that need config values)
	Config *config.Config

	// Cache provides cache access for interceptors (rate limiting)
	Cache cache.CacheWithCounter

	// RealIP provides trusted-proxy-aware client IP extraction.
	RealIP *realip.TrustedProxies
}
