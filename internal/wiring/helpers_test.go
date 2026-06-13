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
		FastAuth:                f.FastAuth,
		SkipCrypto:              f.SkipCrypto,
		SkipPeerTrust:           f.SkipPeerTrust,
		SkipSignatureMiddleware: f.SkipSignatureMiddleware,
		OutboundOverride:        f.OutboundOverride,
		SkipDiscoveryCache:      f.SkipDiscoveryCache,
	}
}
