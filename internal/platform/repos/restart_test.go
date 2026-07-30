package repos_test

import (
	"context"
	"testing"
	"time"

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
	ctx := context.Background()

	for _, backend := range tsrepos.DurableBackends() {
		t.Run(backend, func(t *testing.T) {
			dir := t.TempDir()
			cfg := config.PersistenceConfig{
				Backend: backend,
				DataDir: dir,
			}

			// First session: create invites through adapter repos.
			r1, err := repos.New(ctx, cfg)
			if err != nil {
				t.Fatalf("repos.New(%s) session 1: %v", backend, err)
			}

			now := time.Unix(time.Now().Unix(), 0).UTC()

			outInvite := &invitesoutgoing.OutgoingInvite{
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
			if err := r1.OutgoingInvites.Create(ctx, outInvite); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
				t.Fatalf("OutgoingInvites.Create: %v", err)
			}

			inInvite := &invitesincoming.IncomingInvite{
				ID:              "restart-in-" + backend,
				Token:           "restart-in-token-" + backend,
				InviteString:    "b64-in",
				SenderFQDN:      "sender.example",
				RecipientUserID: "recipient-" + backend,
				Status:          invites.InviteStatusPending,
				ReceivedAt:      now,
			}
			if err := r1.IncomingInvites.Create(ctx, inInvite); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
				t.Fatalf("IncomingInvites.Create: %v", err)
			}

			if err := r1.Close(); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
				t.Fatalf("Close session 1: %v", err)
			}

			// Second session: verify adapter-level lookups after reopen.
			r2, err := repos.New(ctx, cfg)
			if err != nil {
				t.Fatalf("repos.New(%s) session 2: %v", backend, err)
			}
			defer func() {
				if err := r2.Close(); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
					t.Errorf("Close() error = %v", err)
				}
			}()

			gotOutByID, err := r2.OutgoingInvites.GetByID(ctx, outInvite.ID)
			if err != nil {
				t.Fatalf("OutgoingInvites.GetByID after restart: %v", err)
			}

			if gotOutByID.Token != outInvite.Token {
				t.Errorf(
					"outgoing invite token mismatch: expected %q, got %q",
					outInvite.Token,
					gotOutByID.Token,
				)
			}

			gotOut, err := r2.OutgoingInvites.GetByToken(ctx, outInvite.Token)
			if err != nil {
				t.Fatalf("OutgoingInvites.GetByToken after restart: %v", err)
			}

			if gotOut.ID != outInvite.ID {
				t.Errorf(
					"outgoing invite ID mismatch: expected %q, got %q",
					outInvite.ID,
					gotOut.ID,
				)
			}

			gotIn, err := r2.IncomingInvites.GetByIDForRecipientUserID(
				ctx, inInvite.ID, inInvite.RecipientUserID,
			)
			if err != nil {
				t.Fatalf("IncomingInvites.GetByIDForRecipientUserID after restart: %v", err)
			}

			if gotIn.Token != inInvite.Token {
				t.Errorf(
					"incoming invite token mismatch: expected %q, got %q",
					inInvite.Token,
					gotIn.Token,
				)
			}

			if gotIn.RecipientUserID != inInvite.RecipientUserID {
				t.Errorf(
					"incoming invite recipient mismatch: expected %q, got %q",
					inInvite.RecipientUserID,
					gotIn.RecipientUserID,
				)
			}

			gotInByToken, err := r2.IncomingInvites.GetByTokenForRecipientUserID(
				ctx, inInvite.Token, inInvite.RecipientUserID,
			)
			if err != nil {
				t.Fatalf("IncomingInvites.GetByTokenForRecipientUserID after restart: %v", err)
			}

			if gotInByToken.ID != inInvite.ID {
				t.Errorf(
					"incoming invite token index mismatch: expected %q, got %q",
					inInvite.ID,
					gotInByToken.ID,
				)
			}
		})
	}
}
