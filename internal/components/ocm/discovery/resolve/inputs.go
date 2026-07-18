package resolve

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
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
	PeerContract      *peercompat.CompiledContract
	PeerIdentity      RequestPeerIdentity
}
