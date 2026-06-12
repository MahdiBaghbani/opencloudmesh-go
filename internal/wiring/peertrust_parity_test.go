package wiring_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func peerTrustCfg(port int) *config.Config {
	cfg := wiringtest.DevConfigNoSignatures(port)
	cfg.PeerTrust.Enabled = true
	cfg.PeerTrust.ConfigPaths = []string{}
	return cfg
}

func TestPeerTrustParity_SkipPeerTrustGatesDeps(t *testing.T) {
	t.Run("SkipPeerTrust=true with PeerTrust.Enabled=true produces nil trust deps", func(t *testing.T) {
		opts := harnessBuildOpts()
		result, err := wiring.Build(peerTrustCfg(18084), wiringtest.DiscardLogger(), opts)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := result.Deps
		if d.TrustGroupMgr != nil {
			t.Error("TrustGroupMgr must be nil when SkipPeerTrust=true")
		}
		if d.PolicyEngine != nil {
			t.Error("PolicyEngine must be nil when SkipPeerTrust=true")
		}
	})

	t.Run("SkipPeerTrust=false with PeerTrust.Enabled=true produces non-nil trust deps", func(t *testing.T) {
		opts := harnessBuildOpts()
		opts.SkipPeerTrust = false
		result, err := wiring.Build(peerTrustCfg(18085), wiringtest.DiscardLogger(), opts)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := result.Deps
		if d.TrustGroupMgr == nil {
			t.Error("TrustGroupMgr must be non-nil when SkipPeerTrust=false and PeerTrust.Enabled=true")
		}
		if d.PolicyEngine == nil {
			t.Error("PolicyEngine must be non-nil when SkipPeerTrust=false and PeerTrust.Enabled=true")
		}
	})
}
