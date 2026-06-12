package wiring_test

import (
	wiringtest "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
)

func harnessBuildOpts() wiring.BuildOpts {
	return toBuildOpts(wiringtest.HarnessWireOptions)
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
