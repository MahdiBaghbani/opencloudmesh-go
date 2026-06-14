package wiring

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
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
	IncomingShareRepo  sharesinbox.IncomingShareRepo
	OutgoingShareRepo  sharesoutgoing.OutgoingShareRepo
	OutgoingInviteRepo invitesoutgoing.OutgoingInviteRepo
	IncomingInviteRepo invitesinbox.IncomingInviteRepo
	TokenStore         token.TokenStore

	// Clients
	HTTPClient      *httpclient.ContextClient
	DiscoveryClient *discovery.Client

	// Policy objects created once from frozen config at startup.
	OpenCloudMeshPolicy *policy.OpenCloudMeshPolicy
	RuntimePolicy       *policy.RuntimePolicy

	// Crypto
	KeyManager          *crypto.KeyManager
	Signer              *crypto.RFC9421Signer
	OutboundPolicy      *outboundsigning.OutboundPolicy
	SignatureMiddleware *signature.SignatureMiddleware

	// Peer trust (optional)
	TrustGroupMgr *peertrust.TrustGroupManager
	PolicyEngine  *peertrust.PolicyEngine
	PeerContract  *peercompat.CompiledContract

	// LocalIdentity is the SSOT for published public identity derived at startup.
	LocalIdentity localidentity.Identity

	// Config (for handlers that need config values)
	Config *config.Config

	// Cache provides cache access for interceptors (rate limiting)
	Cache cache.CacheWithCounter

	// RealIP provides trusted-proxy-aware client IP extraction.
	RealIP *realip.TrustedProxies
}
