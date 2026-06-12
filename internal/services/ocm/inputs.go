package ocm

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
)

// Inputs holds dependencies for the OCM service constructor.
type Inputs struct {
	IncomingShareRepo           sharesinbox.IncomingShareRepo
	OutgoingShareRepo           sharesoutgoing.OutgoingShareRepo
	OutgoingInviteRepo          invitesoutgoing.OutgoingInviteRepo
	PartyRepo                   identity.PartyRepo
	PolicyEngine                *peertrust.PolicyEngine
	DiscoveryClient             *discovery.Client
	OpenCloudMeshPolicy         *policy.OpenCloudMeshPolicy
	RuntimePolicy               *policy.RuntimePolicy
	PeerContract                *peercompat.CompiledContract
	LocalProviderFQDN           string
	LocalProviderFQDNForCompare string
	TokenStore                  token.TokenStore
	SignatureMiddleware         *inboundsignature.SignatureMiddleware
	PublicOrigin                string
	PublicScheme                string
	TokenExchangePath           string
}
