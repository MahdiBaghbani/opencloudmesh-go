// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring_test

import (
	tswiring "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
)

func harnessBuildOpts() wiring.BuildOpts {
	return toBuildOpts(tswiring.HarnessWireOptions)
}

func toBuildOpts(f tswiring.FixtureBuildOpts) wiring.BuildOpts {
	return wiring.BuildOpts{
		FastAuth:           f.FastAuth,
		SkipCrypto:         f.SkipCrypto,
		SkipPeerTrust:      f.SkipPeerTrust,
		OutboundOverride:   f.OutboundOverride,
		SkipDiscoveryCache: f.SkipDiscoveryCache,
	}
}
