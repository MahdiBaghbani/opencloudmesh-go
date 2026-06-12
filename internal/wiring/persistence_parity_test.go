package wiring_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func assertMemoryBackedTokenStore(t *testing.T, d *deps.Deps) {
	t.Helper()
	if d.TokenStore == nil {
		t.Fatal("TokenStore must be non-nil")
	}
	if _, ok := d.TokenStore.(*token.MemoryTokenStore); !ok {
		t.Errorf("TokenStore must stay memory-backed, got %T", d.TokenStore)
	}
}

func TestPersistenceParity_MemoryBackend(t *testing.T) {
	cfg := wiringtest.DevConfigHarness(18094)

	deps.ResetDeps()
	result, err := wiring.Build(cfg, wiringtest.DiscardLogger(), wiringtest.HarnessWireOptions())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	d := deps.GetDeps()
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

func TestPersistenceParity_JSONBackend(t *testing.T) {
	cfg := wiringtest.DevConfigHarness(18096)
	cfg.Persistence.Backend = config.BackendJSON
	cfg.Persistence.DataDir = t.TempDir()

	deps.ResetDeps()
	result, err := wiring.Build(cfg, wiringtest.DiscardLogger(), wiringtest.HarnessWireOptions())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	d := deps.GetDeps()
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

func TestPersistenceParity_RejectsUnknownBackend(t *testing.T) {
	cfg := wiringtest.DevConfigHarness(18095)
	cfg.Persistence.Backend = "bogus-not-a-backend"

	deps.ResetDeps()
	_, err := wiring.Build(cfg, wiringtest.DiscardLogger(), wiringtest.HarnessWireOptions())
	if err == nil {
		t.Fatal("Build must fail for unknown persistence backend")
	}
}
