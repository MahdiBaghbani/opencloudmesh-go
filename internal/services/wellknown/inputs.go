package wellknown

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
)

// Inputs holds dependencies for the wellknown service constructor.
type Inputs struct {
	Resolve             resolve.ResolveInputs
	SignatureMiddleware *inboundsignature.SignatureMiddleware
}
