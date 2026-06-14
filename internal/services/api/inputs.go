package api

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// Inputs holds dependencies for the API service constructor.
type Inputs struct {
	PartyRepo           identity.PartyRepo
	SessionRepo         identity.SessionRepo
	UserAuth            *identity.UserAuth
	IncomingShareRepo   sharesinbox.IncomingShareRepo
	OutgoingShareRepo   sharesoutgoing.OutgoingShareRepo
	IncomingInviteRepo  invitesinbox.IncomingInviteRepo
	OutgoingInviteRepo  invitesoutgoing.OutgoingInviteRepo
	HTTPClient          *httpclient.ContextClient
	DiscoveryClient     *discovery.Client
	Signer              *crypto.RFC9421Signer
	OutboundPolicy      *outboundsigning.OutboundPolicy
	OpenCloudMeshPolicy *policy.OpenCloudMeshPolicy
	PeerContract        *peercompat.CompiledContract
	LocalIdentity       localidentity.Identity
	Ratelimit           ratelimit.Inputs
	InterceptorProfiles map[string]map[string]any
}
