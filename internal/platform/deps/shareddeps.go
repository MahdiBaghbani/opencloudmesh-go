// Package deps provides shared dependencies for all services.
// See docs/concepts/service-registry.md for details.
package deps

import (
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

var (
	sharedDeps     *Deps
	sharedDepsOnce sync.Once
)

// Deps holds shared dependencies for all services.
// This is the opencloudmesh-go equivalent of Reva's sharedconf,
// adapted for a monolith where services share in-memory repos.
type Deps struct {
	// Identity (for session-gated endpoints)
	PartyRepo   identity.PartyRepo
	SessionRepo identity.SessionRepo
	UserAuth    *identity.UserAuth

	// Repos
	IncomingShareRepo  shares.IncomingShareRepo
	OutgoingShareRepo  sharesoutgoing.OutgoingShareRepo
	OutgoingInviteRepo invites.OutgoingInviteRepo
	IncomingInviteRepo invites.IncomingInviteRepo
	TokenStore         token.TokenStore

	// Clients
	HTTPClient      *httpclient.ContextClient
	DiscoveryClient *discovery.Client

	// Crypto
	KeyManager          *crypto.KeyManager
	Signer              *crypto.RFC9421Signer
	OutboundPolicy      *outboundsigning.OutboundPolicy
	SignatureMiddleware *crypto.SignatureMiddleware

	// Peer trust (optional)
	TrustGroupMgr   *peertrust.TrustGroupManager
	PolicyEngine    *peertrust.PolicyEngine
	ProfileRegistry *peercompat.ProfileRegistry

	// Provider identity derived from PublicOrigin at startup
	LocalProviderFQDN           string // raw host[:port] from PublicOrigin (lowercased)
	LocalProviderFQDNForCompare string // scheme-aware normalized (default port stripped)

	// Config (for handlers that need config values)
	Config *config.Config

	// Cache provides cache access for interceptors (rate limiting)
	Cache cache.CacheWithCounter

	// RealIP provides trusted-proxy-aware client IP extraction.
	// This is the single source of truth for client identity in logging and rate limiting.
	RealIP *realip.TrustedProxies
}

// SetDeps sets the shared dependencies. Must be called once at startup
// before any services are constructed.
func SetDeps(d *Deps) {
	sharedDepsOnce.Do(func() {
		sharedDeps = d
	})
}

// GetDeps returns the shared dependencies.
// Returns nil if SetDeps has not been called.
func GetDeps() *Deps {
	return sharedDeps
}

// ResetDeps is for testing only. Resets the singleton.
func ResetDeps() {
	sharedDeps = nil
	sharedDepsOnce = sync.Once{}
}
