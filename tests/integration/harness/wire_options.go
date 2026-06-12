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
		OutboundOverride: &config.OutboundHTTPConfig{
			SSRF:               config.SSRFConfig{Mode: "off"},
			SSRFMode:           "off",
			TimeoutMS:          5000,
			ConnectTimeoutMS:   2000,
			MaxRedirects:       1,
			MaxResponseBytes:   1048576,
			InsecureSkipVerify: true,
		},
		SkipDiscoveryCache: true,
	}
}
