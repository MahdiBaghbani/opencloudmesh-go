package harness

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
)

// IntegrationBuildOpts returns the wiring.BuildOpts used by StartTestServerWithConfig.
func IntegrationBuildOpts() wiring.BuildOpts {
	return wiring.BuildOpts{
		FastAuth:                true,
		SkipCrypto:              true,
		SkipPeerTrust:           true,
		SkipSignatureMiddleware: true,
		OutboundOverride:        config.TestHarnessOutboundHTTP(),
		SkipDiscoveryCache:      true,
	}
}
