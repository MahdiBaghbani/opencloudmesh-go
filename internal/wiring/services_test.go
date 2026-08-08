// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/server"
)

func TestBuildCoreServices_FailsWithoutSharedDeps(t *testing.T) {
	t.Parallel()

	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := BuildCoreServices(cfg, logger, nil)
	if err == nil {
		t.Fatal("expected error when shared deps are nil")
	}

	if !errors.Is(err, server.ErrMissingServerDeps) {
		t.Fatalf("expected ErrMissingServerDeps, got: %v", err)
	}
}

func TestBuildCoreServices_FailsWithoutRealIP(t *testing.T) {
	t.Parallel()

	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	d := &Deps{
		PartyRepo:   identity.NewMemoryPartyRepo(),
		SessionRepo: identity.NewMemorySessionRepo(),
	}

	_, err := BuildCoreServices(cfg, logger, d)
	if err == nil {
		t.Fatal("expected error when RealIP is nil")
	}

	if !errors.Is(err, server.ErrMissingRealIP) {
		t.Fatalf("expected ErrMissingRealIP before ratelimit wiring, got: %v", err)
	}
}
