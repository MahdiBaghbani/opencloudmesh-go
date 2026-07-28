package wellknown

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	// RouteWellKnownOCM is the well-known OCM route path.
	RouteWellKnownOCM = "/.well-known/ocm"
	// RouteWellKnownOCMSlash is the well-known OCM route path with trailing slash.
	RouteWellKnownOCMSlash = "/.well-known/ocm/"
	// RouteWellKnownJWKS is the well-known JWKS route path.
	RouteWellKnownJWKS = "/.well-known/jwks.json"
)

func init() {
	service.RegisterRouteSpecs(registeredRouteSpecs)
}

func registeredRouteSpecs(service.RouteOpts) []service.RouteSpec {
	return []service.RouteSpec{
		{
			ID:              "wellknown-ocm",
			Service:         "wellknown",
			Method:          "GET",
			Pattern:         RouteWellKnownOCM,
			SessionPolicy:   service.SessionPublic,
			HandlerAuth:     service.HandlerAuthNone,
			SurfaceClass:    service.SurfaceDiscovery,
			DiscoveryFields: []string{"end-point", "provider"},
			TrustClass:      service.TrustPeerNone,
		},
		{
			ID:              "wellknown-ocm-slash",
			Service:         "wellknown",
			Method:          "GET",
			Pattern:         RouteWellKnownOCMSlash,
			SessionPolicy:   service.SessionPublic,
			HandlerAuth:     service.HandlerAuthNone,
			SurfaceClass:    service.SurfaceDiscovery,
			DiscoveryFields: []string{"end-point", "provider"},
			TrustClass:      service.TrustPeerNone,
		},
		{
			ID:              "wellknown-jwks",
			Service:         "wellknown",
			Method:          "GET",
			Pattern:         RouteWellKnownJWKS,
			SessionPolicy:   service.SessionPublic,
			HandlerAuth:     service.HandlerAuthNone,
			SurfaceClass:    service.SurfaceDiscovery,
			DiscoveryFields: []string{"jwks"},
			TrustClass:      service.TrustPeerNone,
		},
	}
}
