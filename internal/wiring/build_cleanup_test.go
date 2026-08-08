// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	tswiring "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/wiring"
)

func TestBuild_ClosesPersistenceWhenWireSharedDepsFails(t *testing.T) { //nolint:paralleltest // mutates package-level wireSharedDepsHook and closePersistenceOnBootstrapFailure hooks restored in t.Cleanup
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
		return BuildResult{}, errors.New("injected wire failure")
	}

	t.Cleanup(func() { wireSharedDepsHook = oldWire })

	cfg := config.DevConfig()

	_, err := Build(cfg, tslog.DiscardLogger(), harnessBuildOptsForPackageTest(tswiring.HarnessWireOptions))
	if err == nil {
		t.Fatal("expected wire shared deps failure")
	}

	if !closeCalled.Load() {
		t.Fatal("Build must close persistence when wireSharedDeps fails after repos.New")
	}
}

func TestWireSharedDeps_RejectsNilPersistence(t *testing.T) {
	t.Parallel()

	cfg := config.DevConfig()

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
		FastAuth:           f.FastAuth,
		SkipCrypto:         f.SkipCrypto,
		SkipPeerTrust:      f.SkipPeerTrust,
		OutboundOverride:   f.OutboundOverride,
		SkipDiscoveryCache: f.SkipDiscoveryCache,
	}
}
