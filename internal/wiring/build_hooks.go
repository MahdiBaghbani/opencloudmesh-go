// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

type wireSharedDepsFunc func(
	*config.Config,
	*slog.Logger,
	BuildOpts,
	*repos.Repos,
) (BuildResult, error)

type closePersistenceFunc func(*repos.Repos, *slog.Logger)

// Package-level seams are overwritten by wiring tests; do not use t.Parallel()
// in tests that mutate wireSharedDepsHook without restoring these defaults.
var (
	wireSharedDepsHook                 wireSharedDepsFunc   = wireSharedDeps
	closePersistenceOnBootstrapFailure closePersistenceFunc = defaultClosePersistenceOnBootstrapFailure
)

func defaultClosePersistenceOnBootstrapFailure(persistenceRepos *repos.Repos, logger *slog.Logger) {
	if closeErr := persistenceRepos.Close(); closeErr != nil {
		logger.Warn("close persistence after bootstrap failure", "error", closeErr)
	}
}
