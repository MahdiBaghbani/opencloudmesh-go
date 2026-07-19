package ocm

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	RouteShares         = "/shares"
	RouteInviteAccepted = "/invite-accepted"
)

func init() {
	service.RegisterRouteSpecs(registeredRouteSpecs)
}

func tokenRoutePattern(opts service.RouteOpts) string {
	path := opts.TokenExchangePath
	if path == "" {
		path = "token"
	}
	return "/" + path
}

func registeredRouteSpecs(opts service.RouteOpts) []service.RouteSpec {
	tokenPattern := tokenRoutePattern(opts)
	return []service.RouteSpec{
		{
			ID:             "ocm-shares",
			Service:        "ocm",
			Method:         "POST",
			Pattern:        RouteShares,
			SessionPolicy:  service.SessionPublic,
			HandlerAuth:    service.HandlerAuthRequiredHTTPSig,
			SurfaceClass:   service.SurfaceProtocol,
			TrustClass:     service.TrustPeerRequired,
			BodyLimitBytes: service.OCMProtocolBodyLimitBytes,
			PeerResolution: service.PeerResolutionShares,
		},
		{
			ID:             "ocm-invite-accepted",
			Service:        "ocm",
			Method:         "POST",
			Pattern:        RouteInviteAccepted,
			SessionPolicy:  service.SessionPublic,
			HandlerAuth:    service.HandlerAuthRequiredHTTPSig,
			SurfaceClass:   service.SurfaceProtocol,
			TrustClass:     service.TrustPeerRequired,
			BodyLimitBytes: service.OCMProtocolBodyLimitBytes,
			PeerResolution: service.PeerResolutionInviteAccepted,
		},
		{
			ID:              service.RouteIDOCMToken,
			Service:         "ocm",
			Method:          "POST",
			Pattern:         tokenPattern,
			SessionPolicy:   service.SessionPublic,
			HandlerAuth:     service.HandlerAuthRequiredHTTPSig,
			SurfaceClass:    service.SurfaceProtocol,
			TrustClass:      service.TrustPeerRequired,
			DiscoveryFields: []string{"tokenEndPoint"},
			BodyLimitBytes:  service.OCMProtocolBodyLimitBytes,
			PeerResolution:  service.PeerResolutionToken,
		},
	}
}
