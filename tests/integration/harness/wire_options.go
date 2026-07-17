package harness

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
)

// IntegrationBuildOpts returns the wiring.BuildOpts used by StartTestServerWithConfig.
// Crypto keys and inbound signature middleware match production posture; FastAuth,
// SkipPeerTrust, harness outbound override, and SkipDiscoveryCache remain test
// transport shortcuts.
func IntegrationBuildOpts() wiring.BuildOpts {
	return wiring.BuildOpts{
		FastAuth:           true,
		SkipCrypto:         false,
		SkipPeerTrust:      true,
		OutboundOverride:   config.TestHarnessOutboundHTTP(),
		SkipDiscoveryCache: true,
	}
}

// OutgoingSharePolicyBuildOpts returns the integration harness baseline. Outbound
// signing keys and policy are already enabled by IntegrationBuildOpts.
func OutgoingSharePolicyBuildOpts() wiring.BuildOpts {
	return IntegrationBuildOpts()
}

// IETFIntegrationBuildOpts returns wiring.BuildOpts for HTTP signature integration
// tests. Identical to IntegrationBuildOpts after the harness converged on real
// crypto and signature middleware.
func IETFIntegrationBuildOpts() wiring.BuildOpts {
	return IntegrationBuildOpts()
}
