package ocm

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// Inputs holds dependencies for the OCM service constructor.
type Inputs struct {
	IncomingShareRepo   sharesinbox.IncomingShareRepo
	OutgoingShareRepo   sharesoutgoing.OutgoingShareRepo
	OutgoingInviteRepo  invitesoutgoing.OutgoingInviteRepo
	PartyRepo           identity.PartyRepo
	PolicyEngine        *peertrust.PolicyEngine
	CodeFlow            *policy.CodeFlow
	LocalIdentity       localidentity.Identity
	TokenStore          token.TokenStore
	SignatureMiddleware *inboundsignature.SignatureMiddleware
	TokenExchangePath   string
}
