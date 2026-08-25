// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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
		OutboundDialHosts:  map[string]string{"validator-peer.test": "127.0.0.1"},
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
