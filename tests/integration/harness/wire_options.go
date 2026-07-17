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

// OutgoingSharePolicyBuildOpts enables outbound signing keys and policy while
// keeping the default integration harness transport and middleware shortcuts.
func OutgoingSharePolicyBuildOpts() wiring.BuildOpts {
	opts := IntegrationBuildOpts()
	opts.SkipCrypto = false
	return opts
}

// IETFIntegrationBuildOpts returns wiring.BuildOpts for HTTP signature integration
// tests that exercise real crypto and inbound signature middleware.
func IETFIntegrationBuildOpts() wiring.BuildOpts {
	opts := IntegrationBuildOpts()
	opts.SkipCrypto = false
	opts.SkipSignatureMiddleware = false
	return opts
}
