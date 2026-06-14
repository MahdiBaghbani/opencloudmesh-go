package wellknown

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	RouteWellKnownOCM      = "/.well-known/ocm"
	RouteWellKnownOCMSlash = "/.well-known/ocm/"
	RouteOCMProvider       = "/ocm-provider"
	RouteOCMProviderSlash  = "/ocm-provider/"
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
			ID:              "wellknown-ocm-provider",
			Service:         "wellknown",
			Method:          "GET",
			Pattern:         RouteOCMProvider,
			SessionPolicy:   service.SessionPublic,
			HandlerAuth:     service.HandlerAuthNone,
			SurfaceClass:    service.SurfaceDiscovery,
			DiscoveryFields: []string{"end-point", "provider"},
			TrustClass:      service.TrustPeerNone,
		},
		{
			ID:              "wellknown-ocm-provider-slash",
			Service:         "wellknown",
			Method:          "GET",
			Pattern:         RouteOCMProviderSlash,
			SessionPolicy:   service.SessionPublic,
			HandlerAuth:     service.HandlerAuthNone,
			SurfaceClass:    service.SurfaceDiscovery,
			DiscoveryFields: []string{"end-point", "provider"},
			TrustClass:      service.TrustPeerNone,
		},
	}
}
