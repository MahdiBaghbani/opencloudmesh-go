// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"log/slog"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity/sessiongate"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/server"
)

// BuildServerDeps assembles narrow server dependencies from explicit wiring deps.
func BuildServerDeps(cfg *config.Config, log *slog.Logger, d *Deps) (server.ServerDeps, error) {
	if d == nil {
		return server.ServerDeps{}, server.ErrMissingServerDeps
	}

	if d.RealIP == nil {
		return server.ServerDeps{}, server.ErrMissingRealIP
	}

	if d.SessionRepo == nil || d.PartyRepo == nil {
		return server.ServerDeps{}, server.ErrMissingAuthRepos
	}

	return server.ServerDeps{
		RealIP: d.RealIP,
		AuthGate: func(requireAuth func(string) bool) func(http.Handler) http.Handler {
			return sessiongate.NewAuthGate(sessiongate.AuthGateConfig{
				RequireAuth: requireAuth,
				Log:         log,
				SessionRepo: d.SessionRepo,
				PartyRepo:   d.PartyRepo,
				BasePath:    cfg.ExternalBasePath,
			})
		},
	}, nil
}
