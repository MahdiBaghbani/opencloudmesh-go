package resolve

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// ResolveInputs bundles the cross-cutting values discovery resolution needs.
// Wiring assembles this struct; resolve does not read the global deps bag.
type ResolveInputs struct {
	LocalIdentity     localidentity.Identity
	RouteOpts         service.RouteOpts
	TokenExchangePath string
	KeyManager        *crypto.KeyManager
	CodeFlow          *policy.CodeFlow
	// Resolver is the scope-gated peer-mapping resolver that drives discovery
	// criteria and capabilities. When nil, Resolve falls back to CodeFlow.Evaluate.
	Resolver *policy.PeerMappingResolver
	// JwksURIOverride is the configured signature.jwks_uri override. Empty
	// means derive the advertised jwksUri from the route-inventory projection
	// (the GET /jwks route's DiscoveryFields projection), not a fixed path.
	JwksURIOverride string
}
