package webdav

import (
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
)

func testWebDAVInputs() Inputs {
	return Inputs{
		OutgoingShareRepo: sharesoutgoing.NewMemoryOutgoingShareRepo(),
		TokenStore:        token.NewMemoryTokenStore(),
	}
}
