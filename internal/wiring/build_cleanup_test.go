package wiring

import (
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"
)

func TestBuild_ClosesPersistenceWhenBootstrapFails(t *testing.T) {
	deps.ResetDeps()
	t.Cleanup(deps.ResetDeps)

	deps.SetDeps(&deps.Deps{})

	var closeCalled atomic.Bool
	oldClose := closePersistenceOnBootstrapFailure
	closePersistenceOnBootstrapFailure = func(persistenceRepos *repos.Repos, logger *slog.Logger) {
		closeCalled.Store(true)
		defaultClosePersistenceOnBootstrapFailure(persistenceRepos, logger)
	}
	t.Cleanup(func() { closePersistenceOnBootstrapFailure = oldClose })

	cfg := wiringtest.DevConfigHarness(18200)
	_, err := Build(cfg, wiringtest.DiscardLogger(), wiringtest.HarnessWireOptions())
	if err == nil {
		t.Fatal("expected bootstrap failure when deps are already set")
	}
	if !strings.Contains(err.Error(), "bootstrap deps:") {
		t.Fatalf("expected wrapped bootstrap error, got: %v", err)
	}
	if !closeCalled.Load() {
		t.Fatal("Build must close persistence when bootstrap fails after repos.New")
	}
}
