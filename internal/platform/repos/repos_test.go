package repos_test

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"
)

// ---- backend selection ----

func TestNew_MemoryBackend(t *testing.T) {
	ctx := context.Background()
	cfg := config.PersistenceConfig{Backend: config.BackendMemory}

	r, err := repos.New(ctx, cfg)
	if err != nil {
		t.Fatalf("New(memory) error = %v", err)
	}
	defer r.Close()

	if r.OutgoingShares == nil {
		t.Error("OutgoingShares is nil")
	}
	if r.IncomingShares == nil {
		t.Error("IncomingShares is nil")
	}
	if r.OutgoingInvites == nil {
		t.Error("OutgoingInvites is nil")
	}
	if r.IncomingInvites == nil {
		t.Error("IncomingInvites is nil")
	}
}

func TestNew_JSONBackend(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	cfg := config.PersistenceConfig{
		Backend: config.BackendJSON,
		DataDir: dir,
	}

	r, err := repos.New(ctx, cfg)
	if err != nil {
		t.Fatalf("New(json) error = %v", err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	if r.OutgoingShares == nil {
		t.Error("OutgoingShares is nil")
	}
	if r.IncomingShares == nil {
		t.Error("IncomingShares is nil")
	}
	if r.OutgoingInvites == nil {
		t.Error("OutgoingInvites is nil")
	}
	if r.IncomingInvites == nil {
		t.Error("IncomingInvites is nil")
	}
}

func TestNew_SQLiteBackend(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	cfg := config.PersistenceConfig{
		Backend: config.BackendSQLite,
		DataDir: dir,
	}

	r, err := repos.New(ctx, cfg)
	if err != nil {
		t.Fatalf("New(sqlite) error = %v", err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	if r.OutgoingShares == nil {
		t.Error("OutgoingShares is nil")
	}
	if r.IncomingShares == nil {
		t.Error("IncomingShares is nil")
	}
	if r.OutgoingInvites == nil {
		t.Error("OutgoingInvites is nil")
	}
	if r.IncomingInvites == nil {
		t.Error("IncomingInvites is nil")
	}
}

func TestNew_MirrorBackend(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	cfg := config.PersistenceConfig{
		Backend: config.BackendMirror,
		DataDir: dir,
	}

	r, err := repos.New(ctx, cfg)
	if err != nil {
		t.Fatalf("New(mirror) error = %v", err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	if r.OutgoingShares == nil {
		t.Error("OutgoingShares is nil")
	}
	if r.IncomingShares == nil {
		t.Error("IncomingShares is nil")
	}
	if r.OutgoingInvites == nil {
		t.Error("OutgoingInvites is nil")
	}
	if r.IncomingInvites == nil {
		t.Error("IncomingInvites is nil")
	}
}

func TestNew_UnknownBackend(t *testing.T) {
	ctx := context.Background()
	cfg := config.PersistenceConfig{Backend: "postgres"}

	_, err := repos.New(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
}

// ---- helpers ----

func newMemoryRepos(t *testing.T) *repos.Repos {
	return tsrepos.OpenMemory(t)
}

func newJSONRepos(t *testing.T) *repos.Repos {
	return tsrepos.OpenJSON(t)
}

func newDurableRepos(t *testing.T, backend string) *repos.Repos {
	return tsrepos.OpenDurable(t, backend)
}
