// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/core"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/statistics"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func buildValidatorCore(cfg *config.Config) (*core.Core, error) {
	if !config.IsValidatorMode(cfg) {
		return nil, nil //nolint:nilnil // validator core is absent outside validator mode
	}

	if !cfg.Statistics.Enabled {
		return nil, errors.New("validator mode requires statistics.enabled=true")
	}

	salt, err := statistics.LoadRedactionSalt(cfg.Persistence.DataDir)
	if err != nil {
		return nil, fmt.Errorf("load redaction salt: %w", err)
	}

	validatorCore, err := core.New(salt)
	if err != nil {
		return nil, fmt.Errorf("build federation validator core: %w", err)
	}

	return validatorCore, nil
}

// buildValidatorPersistence resolves the shared SQLite handle first so JSON
// (or other non-SQLite) persistence fails before redaction salt I/O, then
// builds the hasher and attaches the store so startup maintenance can heal
// missing terminal statistics before tombstone or prune.
func buildValidatorPersistence(
	cfg *config.Config,
	persistence *repos.Repos,
) (*core.Core, *validatorcore.Core, error) {
	validatorDB, err := resolveValidatorSharedDB(cfg, persistence)
	if err != nil {
		return nil, nil, err
	}

	validatorCore, err := buildValidatorCore(cfg)
	if err != nil {
		return nil, nil, err
	}

	validatorStore, err := buildValidatorStore(cfg, validatorDB, validatorCore)
	if err != nil {
		return nil, nil, err
	}

	return validatorCore, validatorStore, nil
}

func resolveValidatorSharedDB(cfg *config.Config, persistence *repos.Repos) (*gorm.DB, error) {
	if !config.IsValidatorMode(cfg) {
		return nil, nil //nolint:nilnil // validator store is absent outside validator mode
	}

	if persistence == nil {
		return nil, errors.New("validator store requires initialized persistence repos")
	}

	db, err := persistence.SharedDB()
	if err != nil {
		return nil, fmt.Errorf("resolve shared SQLite handle for validator store: %w", err)
	}

	return db, nil
}

func buildValidatorStore(
	cfg *config.Config,
	db *gorm.DB,
	hasher validatorcore.StatsHostHasher,
) (*validatorcore.Core, error) {
	if !config.IsValidatorMode(cfg) {
		return nil, nil //nolint:nilnil // validator store is absent outside validator mode
	}

	if db == nil {
		return nil, errors.New("validator store requires initialized persistence repos")
	}

	sessionCfg := config.SessionConfigFromValidator(cfg)

	store, err := validatorcore.AttachWithStatsHasher(db, sessionCfg, hasher)
	if err != nil {
		return nil, fmt.Errorf("attach validator store: %w", err)
	}

	return store, nil
}

// startRetentionSweep starts the hourly expiry loop after a successful Attach.
// Attach stays synchronous. The returned func cancels the loop and waits for
// the goroutine to exit so shutdown can close persistence safely.
func startRetentionSweep(store *validatorcore.Core) context.CancelFunc {
	if store == nil {
		return nil
	}

	sweepCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)

		store.StartRetentionSweep(sweepCtx)
	}()

	return func() {
		cancel()
		<-done
	}
}
