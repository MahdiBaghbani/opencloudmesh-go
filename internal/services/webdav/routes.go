package webdav

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	RouteOCMWildcard = "/ocm/*"
)

func init() {
	service.RegisterRouteSpecs(registeredRouteSpecs)
}

func registeredRouteSpecs(service.RouteOpts) []service.RouteSpec {
	return []service.RouteSpec{
		{
			ID:            service.RouteIDWebDAVOCMWildcard,
			Service:       "webdav",
			Method:        "*",
			Pattern:       RouteOCMWildcard,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthBearer,
			SurfaceClass:  service.SurfaceWebDAV,
			TrustClass:    service.TrustPeerNone,
		},
	}
}
