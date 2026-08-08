// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package repos

import (
	"context"
	"fmt"

	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"

	// Register store drivers via their init() functions.
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/json"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/memory"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/mirror"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlite"
)

// Repos holds the four app-level repository interfaces produced by the seam.
// Callers must call Close when done to release resources held by the backing
// store driver.
type Repos struct {
	OutgoingShares  sharesoutgoing.OutgoingShareRepo
	IncomingShares  sharesincoming.IncomingShareRepo
	OutgoingInvites invitesoutgoing.OutgoingInviteRepo
	IncomingInvites invitesincoming.IncomingInviteRepo

	// driver is the backing store driver for every backend.
	driver store.Driver
}

// Close releases resources held by the backing store driver.
func (r *Repos) Close() error {
	if err := r.driver.Close(); err != nil {
		return fmt.Errorf("repos: close driver: %w", err)
	}

	return nil
}

// New constructs app repos from a PersistenceConfig.
// Every backend (memory, json, sqlite, mirror) resolves through the store
// driver registry: the driver is opened and initialized, then each store
// surface is wrapped in an app-repo adapter.
//
// Returns a clear error for unknown backend values without silent fallback.
func New(ctx context.Context, cfg config.PersistenceConfig) (*Repos, error) {
	switch cfg.Backend {
	case config.BackendMemory, config.BackendJSON, config.BackendSQLite, config.BackendMirror:
		return newStoreRepos(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown persistence backend %q: must be one of memory, json, sqlite, mirror", cfg.Backend)
	}
}

// fullStore is the union of all four store surfaces every store driver must
// implement.
type fullStore interface {
	store.OutgoingShareStore
	store.IncomingShareStore
	store.OutgoingInviteStore
	store.IncomingInviteStore
}

func newStoreRepos(ctx context.Context, cfg config.PersistenceConfig) (*Repos, error) {
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
