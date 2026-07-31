// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func assertMemoryBackedTokenStore(t *testing.T, d *wiring.Deps) {
	t.Helper()

	if d.TokenStore == nil {
		t.Fatal("TokenStore must be non-nil")
	}

	if _, ok := d.TokenStore.(*token.MemoryTokenStore); !ok {
		t.Errorf("TokenStore must stay memory-backed, got %T", d.TokenStore)
	}
}

func TestPersistence_MemoryBackend(t *testing.T) {
	cfg := config.DevConfig()

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	d := result.Deps
	if d.IncomingShareRepo == nil {
		t.Error("IncomingShareRepo must be non-nil")
	}

	if d.OutgoingShareRepo == nil {
		t.Error("OutgoingShareRepo must be non-nil")
	}

	if d.OutgoingInviteRepo == nil {
		t.Error("OutgoingInviteRepo must be non-nil")
	}

	if d.IncomingInviteRepo == nil {
		t.Error("IncomingInviteRepo must be non-nil")
	}

	if result.Persistence == nil {
		t.Fatal("Persistence must be non-nil")
	}

	assertMemoryBackedTokenStore(t, d)

	if err := result.Persistence.Close(); err != nil {
		t.Errorf("Persistence.Close() for memory backend: %v", err)
	}
}

func TestPersistence_JSONBackend(t *testing.T) {
	cfg := config.DevConfig()
	cfg.Persistence.Backend = config.BackendJSON
	cfg.Persistence.DataDir = t.TempDir()

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	d := result.Deps
	if d.IncomingShareRepo == nil {
		t.Error("IncomingShareRepo must be non-nil")
	}

	if d.OutgoingShareRepo == nil {
		t.Error("OutgoingShareRepo must be non-nil")
	}

	if d.OutgoingInviteRepo == nil {
		t.Error("OutgoingInviteRepo must be non-nil")
	}

	if d.IncomingInviteRepo == nil {
		t.Error("IncomingInviteRepo must be non-nil")
	}

	if result.Persistence == nil {
		t.Fatal("Persistence must be non-nil")
	}

	assertMemoryBackedTokenStore(t, d)

	if err := result.Persistence.Close(); err != nil {
		t.Errorf("Persistence.Close() for json backend: %v", err)
	}
}

func TestPersistence_RejectsUnknownBackend(t *testing.T) {
	cfg := config.DevConfig()
	cfg.Persistence.Backend = "bogus-not-a-backend"

	_, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err == nil {
		t.Fatal("Build must fail for unknown persistence backend")
	}
}
