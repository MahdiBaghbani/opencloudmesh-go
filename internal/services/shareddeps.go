// Package services provides Reva-aligned service registry infrastructure.
// See docs/concepts/service-registry.md for details.
package services

import (
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/httpclient"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/token"
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
	OutgoingShareRepo  shares.OutgoingShareRepo
	OutgoingInviteRepo invites.OutgoingInviteRepo
	IncomingInviteRepo invites.IncomingInviteRepo
	TokenStore         token.TokenStore

	// Clients
	HTTPClient      *httpclient.ContextClient
	DiscoveryClient *discovery.Client

	// Crypto
	KeyManager          *crypto.KeyManager
	Signer              *crypto.RFC9421Signer
	OutboundPolicy      *federation.OutboundPolicy
	SignatureMiddleware *crypto.SignatureMiddleware

	// Federation (optional)
	FederationMgr   *federation.FederationManager
	PolicyEngine    *federation.PolicyEngine
	ProfileRegistry *federation.ProfileRegistry

	// Config (for handlers that need config values)
	Config *config.Config
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
