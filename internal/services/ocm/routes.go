package ocm

import (
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	RouteShares         = "/shares"
	RouteNotifications  = "/notifications"
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
			ID:            "ocm-shares",
			Service:       "ocm",
			Method:        "POST",
			Pattern:       RouteShares,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthOptionalHTTPSig,
			SurfaceClass:  service.SurfaceProtocol,
			TrustClass:    service.TrustPeerRequired,
		},
		{
			ID:            "ocm-notifications",
			Service:       "ocm",
			Method:        "POST",
			Pattern:       RouteNotifications,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthOptionalHTTPSig,
			SurfaceClass:  service.SurfaceProtocol,
			TrustClass:    service.TrustNotificationsSpecial,
		},
		{
			ID:            "ocm-invite-accepted",
			Service:       "ocm",
			Method:        "POST",
			Pattern:       RouteInviteAccepted,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthOptionalHTTPSig,
			SurfaceClass:  service.SurfaceProtocol,
			TrustClass:    service.TrustPeerRequired,
		},
		{
			ID:            fmt.Sprintf("ocm-token-%s", opts.TokenExchangePath),
			Service:       "ocm",
			Method:        "POST",
			Pattern:       tokenPattern,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthOptionalHTTPSig,
			SurfaceClass:  service.SurfaceProtocol,
			TrustClass:    service.TrustPeerRequired,
		},
	}
}
