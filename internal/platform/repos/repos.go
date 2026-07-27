package repos

import (
	"context"
	"fmt"

	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"

	// Register durable store drivers via their init() functions.
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/json"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/mirror"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlite"
)

// Repos holds the four app-level repository interfaces produced by the seam.
// Callers must call Close when done to release resources held by durable
// backends. Close is a no-op for the memory backend.
type Repos struct {
	OutgoingShares  sharesoutgoing.OutgoingShareRepo
	IncomingShares  sharesinbox.IncomingShareRepo
	OutgoingInvites invitesoutgoing.OutgoingInviteRepo
	IncomingInvites invitesinbox.IncomingInviteRepo

	// driver is non-nil for durable backends; nil for memory.
	driver store.Driver
}

// Close releases resources held by durable backends. Safe to call on memory
// backend (no-op).
func (r *Repos) Close() error {
	if r.driver == nil {
		return nil
	}

	return r.driver.Close()
}

// New constructs app repos from a PersistenceConfig.
//   - "memory": returns in-process memory repos; no I/O.
//   - "json", "sqlite", "mirror": opens and initializes the named durable
//     store, then wraps each store surface in an app-repo adapter.
//
// Returns a clear error for unknown backend values without silent fallback.
func New(ctx context.Context, cfg config.PersistenceConfig) (*Repos, error) {
	switch cfg.Backend {
	case config.BackendMemory:
		return newMemoryRepos(), nil
	case config.BackendJSON, config.BackendSQLite, config.BackendMirror:
		return newDurableRepos(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown persistence backend %q: must be one of memory, json, sqlite, mirror", cfg.Backend)
	}
}

func newMemoryRepos() *Repos {
	return &Repos{
		OutgoingShares:  sharesoutgoing.NewMemoryOutgoingShareRepo(),
		IncomingShares:  sharesinbox.NewMemoryIncomingShareRepo(),
		OutgoingInvites: invitesoutgoing.NewMemoryOutgoingInviteRepo(),
		IncomingInvites: invitesinbox.NewMemoryIncomingInviteRepo(),
	}
}

// fullStore is the union of all four store surfaces every durable driver
// must implement.
type fullStore interface {
	store.OutgoingShareStore
	store.IncomingShareStore
	store.OutgoingInviteStore
	store.IncomingInviteStore
}

func newDurableRepos(ctx context.Context, cfg config.PersistenceConfig) (*Repos, error) {
	driverCfg := &store.DriverConfig{
		Driver:  cfg.Backend,
		DataDir: cfg.DataDir,
	}

	drv, err := store.New(driverCfg)
	if err != nil {
		return nil, fmt.Errorf("open %s store: %w", cfg.Backend, err)
	}

	if err := drv.Init(ctx); err != nil {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		drv.Close()
		return nil, fmt.Errorf("init %s store: %w", cfg.Backend, err)
	}

	fs, ok := drv.(fullStore)
	if !ok {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		drv.Close()
		return nil, fmt.Errorf("%s driver does not implement all required store surfaces", cfg.Backend)
	}

	return &Repos{
		OutgoingShares:  &outgoingShareAdapter{s: fs},
		IncomingShares:  &incomingShareAdapter{s: fs},
		OutgoingInvites: &outgoingInviteAdapter{s: fs},
		IncomingInvites: &incomingInviteAdapter{s: fs},
		driver:          drv,
	}, nil
}
