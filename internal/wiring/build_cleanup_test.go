package wiring

import (
	"fmt"
	tscfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/cfg"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	tswiring "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/wiring"
)

func TestBuild_ClosesPersistenceWhenWireSharedDepsFails(t *testing.T) {
	var closeCalled atomic.Bool
	oldClose := closePersistenceOnBootstrapFailure
	closePersistenceOnBootstrapFailure = func(persistenceRepos *repos.Repos, logger *slog.Logger) {
		closeCalled.Store(true)
		defaultClosePersistenceOnBootstrapFailure(persistenceRepos, logger)
	}
	t.Cleanup(func() { closePersistenceOnBootstrapFailure = oldClose })

	oldWire := wireSharedDepsHook
	wireSharedDepsHook = func(
		*config.Config,
		*slog.Logger,
		BuildOpts,
		*repos.Repos,
	) (BuildResult, error) {
		return BuildResult{}, fmt.Errorf("injected wire failure")
	}
	t.Cleanup(func() { wireSharedDepsHook = oldWire })

	cfg := tscfg.DevConfigHarness(18200)
	_, err := Build(cfg, tslog.DiscardLogger(), harnessBuildOptsForPackageTest(tswiring.HarnessWireOptions))
	if err == nil {
		t.Fatal("expected wire shared deps failure")
	}
	if !closeCalled.Load() {
		t.Fatal("Build must close persistence when wireSharedDeps fails after repos.New")
	}
}

func TestWireSharedDeps_RejectsNilPersistence(t *testing.T) {
	cfg := tscfg.DevConfigHarness(18199)
	_, err := wireSharedDeps(cfg, tslog.DiscardLogger(), BuildOpts{}, nil)
	if err == nil {
		t.Fatal("expected error for nil persistence")
	}
	if err.Error() != "wire shared deps: persistence repos must be non-nil" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func harnessBuildOptsForPackageTest(f tswiring.FixtureBuildOpts) BuildOpts {
	return BuildOpts{
		FastAuth:                f.FastAuth,
		SkipCrypto:              f.SkipCrypto,
		SkipPeerTrust:           f.SkipPeerTrust,
		SkipSignatureMiddleware: f.SkipSignatureMiddleware,
		OutboundOverride:        f.OutboundOverride,
		SkipDiscoveryCache:      f.SkipDiscoveryCache,
	}
}
