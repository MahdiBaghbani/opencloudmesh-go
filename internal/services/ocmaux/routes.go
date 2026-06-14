package ocmaux

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	RouteFederations = "/federations"
	RouteDiscover    = "/discover"
)

func init() {
	service.RegisterRouteSpecs(registeredRouteSpecs)
}

func registeredRouteSpecs(service.RouteOpts) []service.RouteSpec {
	return []service.RouteSpec{
		{
			ID:            "ocmaux-federations",
			Service:       "ocmaux",
			Method:        "GET",
			Pattern:       RouteFederations,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthNone,
			SurfaceClass:  service.SurfaceHelper,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "ocmaux-discover",
			Service:       "ocmaux",
			Method:        "GET",
			Pattern:       RouteDiscover,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthRateLimitOnly,
			Middleware:    []string{"ratelimit"},
			SurfaceClass:  service.SurfaceHelper,
			TrustClass:    service.TrustPeerNone,
		},
	}
}
