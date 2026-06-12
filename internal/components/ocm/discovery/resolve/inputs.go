package resolve

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

// ResolveInputs bundles the cross-cutting values discovery resolution needs.
// Wiring assembles this struct; resolve does not read the global deps bag.
type ResolveInputs struct {
	PublicOrigin        string
	ExternalBasePath    string
	TokenExchangePath   string
	KeyManager          *crypto.KeyManager
	OpenCloudMeshPolicy *policy.OpenCloudMeshPolicy
	RuntimePolicy       *policy.RuntimePolicy
	UIWayfEnabled       bool
}
