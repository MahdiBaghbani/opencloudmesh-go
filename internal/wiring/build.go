// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package wiring is the composition root for opencloudmesh-go process startup.
package wiring

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

// Build wires shared infrastructure and returns explicit Deps for callers.
// Callers own config loading, logger setup, admin bootstrapping, posture
// checks, and server lifecycle. On wireSharedDeps failure, Build closes
// persistenceRepos before returning the error.
func Build(cfg *config.Config, logger *slog.Logger, opts BuildOpts) (BuildResult, error) {
	persistenceRepos, err := repos.New(context.Background(), cfg.Persistence)
	if err != nil {
		return BuildResult{}, fmt.Errorf("wire persistence repos: %w", err)
	}

	result, err := wireSharedDepsHook(cfg, logger, opts, persistenceRepos)
	if err != nil {
		closePersistenceOnBootstrapFailure(persistenceRepos, logger)

		return BuildResult{}, fmt.Errorf("wire shared deps: %w", err)
	}

	return result, nil
}
