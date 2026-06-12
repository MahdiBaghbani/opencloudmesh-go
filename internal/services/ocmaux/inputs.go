package ocmaux

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
)

// Inputs holds dependencies for the ocmaux service constructor.
type Inputs struct {
	TrustGroupMgr       *peertrust.TrustGroupManager
	DiscoveryClient     *discovery.Client
	Ratelimit           ratelimit.Inputs
	InterceptorProfiles map[string]map[string]any
}
