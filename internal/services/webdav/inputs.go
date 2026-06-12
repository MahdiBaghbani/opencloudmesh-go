package webdav

import (
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
)

// Inputs holds dependencies for the WebDAV service constructor.
type Inputs struct {
	OutgoingShareRepo sharesoutgoing.OutgoingShareRepo
	TokenStore        token.TokenStore
	PeerContract      *peercompat.CompiledContract
}
