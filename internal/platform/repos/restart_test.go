// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package repos_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

// TestDurableRepos_InviteRestart verifies that durable backends survive a
// repos.New -> Close -> repos.New cycle and that adapter-level invite lookups
// work after reopen. Memory is intentionally excluded (no durable restart).
func TestDurableRepos_InviteRestart(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for _, backend := range tsrepos.DurableBackends() {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()
			cfg := config.PersistenceConfig{
				Backend: backend,
				DataDir: t.TempDir(),
			}
			runInviteRestartSession(t, ctx, cfg)
		})
	}
}

// TestStrictPresetPersistence_DataDirSurvivesRestart is the regression guard
// for the sqlite first-boot fix: from a fresh working directory, the strict
// preset's CWD-relative data dir must be created on demand and the seeded
// invites must survive a restart. Without the MkdirAll in sqlitecore.Open,
// the first repos.New fails because .ocm/data does not exist.
func TestStrictPresetPersistence_DataDirSurvivesRestart(t *testing.T) { //nolint:paralleltest // uses t.Chdir, which mutates process-global cwd and is incompatible with t.Parallel
	root := t.TempDir()
	t.Chdir(root)

	cfg := config.StrictConfig().Persistence
	if cfg.Backend != config.BackendSQLite {
		t.Fatalf("strict preset backend = %q, want %q", cfg.Backend, config.BackendSQLite)
	}

	if cfg.DataDir != config.DefaultPersistenceDataDir {
		t.Fatalf("strict preset data dir = %q, want %q", cfg.DataDir, config.DefaultPersistenceDataDir)
	}

	ctx := context.Background()
	now := time.Unix(time.Now().Unix(), 0).UTC()
	outInvite := newRestartOutgoingInvite(cfg.Backend, now)
	inInvite := newRestartIncomingInvite(cfg.Backend, now)

	seedRestartInvites(t, ctx, cfg, cfg.Backend, outInvite, inInvite)

	if _, err := os.Stat(filepath.Join(cfg.DataDir, "ocm.db")); err != nil {
		t.Fatalf("ocm.db must exist under the strict data dir after first session: %v", err)
	}

	verifyRestartedInvites(t, ctx, cfg, cfg.Backend, outInvite, inInvite)
}

// runInviteRestartSession drives one backend through a create, close, reopen,
// verify cycle.
func runInviteRestartSession(t *testing.T, ctx context.Context, cfg config.PersistenceConfig) {
	t.Helper()

	backend := cfg.Backend
	now := time.Unix(time.Now().Unix(), 0).UTC()
	outInvite := newRestartOutgoingInvite(backend, now)
	inInvite := newRestartIncomingInvite(backend, now)

	seedRestartInvites(t, ctx, cfg, backend, outInvite, inInvite)
	verifyRestartedInvites(t, ctx, cfg, backend, outInvite, inInvite)
}

// newRestartOutgoingInvite builds the outgoing invite fixture for one backend.
func newRestartOutgoingInvite(backend string, now time.Time) *invitesoutgoing.OutgoingInvite {
	return &invitesoutgoing.OutgoingInvite{
		ID:              "restart-out-" + backend,
		Token:           "restart-out-token-" + backend,
		ProviderFQDN:    "provider.example",
		InviteString:    "b64-out",
		RecipientEmail:  "peer@example.com",
		CreatedByUserID: "user1",
		CreatedAt:       now,
		ExpiresAt:       now.Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
}

// newRestartIncomingInvite builds the incoming invite fixture for one backend.
func newRestartIncomingInvite(backend string, now time.Time) *invitesincoming.IncomingInvite {
	return &invitesincoming.IncomingInvite{
		ID:              "restart-in-" + backend,
		Token:           "restart-in-token-" + backend,
		InviteString:    "b64-in",
		SenderFQDN:      "sender.example",
		RecipientUserID: "recipient-" + backend,
		Status:          invites.InviteStatusPending,
		ReceivedAt:      now,
	}
}

// seedRestartInvites opens the first session, creates both invites through the
// adapter repos, and closes.
func seedRestartInvites(t *testing.T, ctx context.Context, cfg config.PersistenceConfig, backend string, outInvite *invitesoutgoing.OutgoingInvite, inInvite *invitesincoming.IncomingInvite) {
	t.Helper()

	r1, err := repos.New(ctx, cfg)
	if err != nil {
		t.Fatalf("repos.New(%s) session 1: %v", backend, err)
	}

	if err := r1.OutgoingInvites.Create(ctx, outInvite); err != nil {
		t.Fatalf("OutgoingInvites.Create: %v", err)
	}

	if err := r1.IncomingInvites.Create(ctx, inInvite); err != nil {
		t.Fatalf("IncomingInvites.Create: %v", err)
	}

	if err := r1.Close(); err != nil {
		t.Fatalf("Close session 1: %v", err)
	}
}

// verifyRestartedInvites reopens the repos and checks adapter-level lookups
// survive the restart.
func verifyRestartedInvites(t *testing.T, ctx context.Context, cfg config.PersistenceConfig, backend string, outInvite *invitesoutgoing.OutgoingInvite, inInvite *invitesincoming.IncomingInvite) {
	t.Helper()

	r2, err := repos.New(ctx, cfg)
	if err != nil {
		t.Fatalf("repos.New(%s) session 2: %v", backend, err)
	}
	defer tshttp.MustClose(t, r2)

	assertRestartedOutgoingInvite(t, ctx, r2, outInvite)
	assertRestartedIncomingInvite(t, ctx, r2, inInvite)
}

// assertRestartedOutgoingInvite checks outgoing ID and token lookups after reopen.
func assertRestartedOutgoingInvite(t *testing.T, ctx context.Context, r2 *repos.Repos, outInvite *invitesoutgoing.OutgoingInvite) {
	t.Helper()

	gotOutByID, err := r2.OutgoingInvites.GetByID(ctx, outInvite.ID)
	if err != nil {
		t.Fatalf("OutgoingInvites.GetByID after restart: %v", err)
	}

	if gotOutByID.Token != outInvite.Token {
		t.Errorf("outgoing invite token mismatch: expected %q, got %q", outInvite.Token, gotOutByID.Token)
	}

	gotOut, err := r2.OutgoingInvites.GetByToken(ctx, outInvite.Token)
	if err != nil {
		t.Fatalf("OutgoingInvites.GetByToken after restart: %v", err)
	}

	if gotOut.ID != outInvite.ID {
		t.Errorf("outgoing invite ID mismatch: expected %q, got %q", outInvite.ID, gotOut.ID)
	}
}

// assertRestartedIncomingInvite checks incoming recipient-scoped lookups after
// reopen.
func assertRestartedIncomingInvite(t *testing.T, ctx context.Context, r2 *repos.Repos, inInvite *invitesincoming.IncomingInvite) {
	t.Helper()

	gotIn, err := r2.IncomingInvites.GetByIDForRecipientUserID(ctx, inInvite.ID, inInvite.RecipientUserID)
	if err != nil {
		t.Fatalf("IncomingInvites.GetByIDForRecipientUserID after restart: %v", err)
	}

	if gotIn.Token != inInvite.Token {
		t.Errorf("incoming invite token mismatch: expected %q, got %q", inInvite.Token, gotIn.Token)
	}

	if gotIn.RecipientUserID != inInvite.RecipientUserID {
		t.Errorf("incoming invite recipient mismatch: expected %q, got %q", inInvite.RecipientUserID, gotIn.RecipientUserID)
	}

	gotInByToken, err := r2.IncomingInvites.GetByTokenForRecipientUserID(ctx, inInvite.Token, inInvite.RecipientUserID)
	if err != nil {
		t.Fatalf("IncomingInvites.GetByTokenForRecipientUserID after restart: %v", err)
	}

	if gotInByToken.ID != inInvite.ID {
		t.Errorf("incoming invite token index mismatch: expected %q, got %q", inInvite.ID, gotInByToken.ID)
	}
}
