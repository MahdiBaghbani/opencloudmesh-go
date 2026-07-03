package wiring_test

import (
	tscfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/cfg"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func peerTrustCfg() *config.Config {
	cfg := tscfg.DevConfigNoSignatures()
	cfg.PeerTrust.Enabled = true
	cfg.PeerTrust.ConfigPaths = []string{}
	return cfg
}

func TestPeerTrustSkip_GatesDeps(t *testing.T) {
	t.Run("SkipPeerTrust=true with PeerTrust.Enabled=true produces nil trust deps", func(t *testing.T) {
		opts := harnessBuildOpts()
		result, err := wiring.Build(peerTrustCfg(), tslog.DiscardLogger(), opts)
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
		result, err := wiring.Build(peerTrustCfg(), tslog.DiscardLogger(), opts)
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
