package wiring_test

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"
)

func harnessBuildOpts() wiring.BuildOpts {
	return toBuildOpts(wiringtest.SnapshotHarnessWireOptions)
}

func toBuildOpts(f wiringtest.FixtureBuildOpts) wiring.BuildOpts {
	return wiring.BuildOpts{
		FastAuth:                f.FastAuth,
		SkipCrypto:              f.SkipCrypto,
		SkipPeerTrust:           f.SkipPeerTrust,
		SkipSignatureMiddleware: f.SkipSignatureMiddleware,
		OutboundOverride:        f.OutboundOverride,
		SkipDiscoveryCache:      f.SkipDiscoveryCache,
	}
}
