package api

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
)

func testAPIInputs() Inputs {
	cfg := config.DevConfig()
	rawHTTP := httpclient.New(nil, nil)
	realIP := realip.NewTrustedProxies(nil)
	return Inputs{
		PartyRepo:           identity.NewMemoryPartyRepo(),
		SessionRepo:         identity.NewMemorySessionRepo(),
		UserAuth:            identity.NewUserAuthFast(),
		IncomingShareRepo:   sharesinbox.NewMemoryIncomingShareRepo(),
		OutgoingShareRepo:   sharesoutgoing.NewMemoryOutgoingShareRepo(),
		IncomingInviteRepo:  invitesinbox.NewMemoryIncomingInviteRepo(),
		OutgoingInviteRepo:  invitesoutgoing.NewMemoryOutgoingInviteRepo(),
		HTTPClient:          httpclient.NewContextClient(rawHTTP),
		DiscoveryClient:     discovery.NewClient(rawHTTP, nil),
		OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
		LocalProviderFQDN:   "localhost",
		Ratelimit: ratelimit.Inputs{
			KeyFunc: realIP.GetClientIPString,
		},
		InterceptorProfiles: cfg.HTTP.Interceptors,
	}
}
