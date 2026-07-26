package incoming_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

func setupTestPartyRepo() identity.PartyRepo {
	repo := identity.NewMemoryPartyRepo()
	ctx := context.Background()
	repo.Create(ctx, &identity.User{
		ID:          "user-a-uuid",
		Username:    "alice",
		Email:       "alice@example.org",
		DisplayName: "Alice A",
	})
	repo.Create(ctx, &identity.User{
		ID:          "user-b-uuid",
		Username:    "bob",
		Email:       "bob@example.org",
		DisplayName: "Bob B",
	})

	return repo
}

// newTestHandler creates a handler wired for testing against localhost:9200 (https).
func newTestHandler(repo *sharesinbox.MemoryIncomingShareRepo, partyRepo identity.PartyRepo) *incoming.Handler {
	return newTestHandlerWithResolver(repo, partyRepo, nil)
}
func validShareBody(shareWith string) string {
	return validShareBodyWithHosts(shareWith, "sender.com")
}

func validShareBodyWithHosts(shareWith, ownerHost string) string {
	return validShareBodyWithOwnerAndSenderHosts(shareWith, ownerHost, ownerHost, "abc123")
}

func validShareBodyWithOwnerAndSenderHosts(shareWith, ownerHost, senderHost, providerID string) string {
	return `{
		"shareWith": "` + shareWith + `",
		"name": "test.txt",
		"providerId": "` + providerID + `",
		"owner": "owner@` + ownerHost + `",
		"sender": "sender@` + senderHost + `",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "webdav",
			"webdav": {
				"uri": "abc123",
				"sharedSecret": "secret123",
				"permissions": ["read"],
				"requirements": ["must-exchange-token"]
			}
		}
	}`
}

func newAcceptedShareHandler(
	t *testing.T,
	repo *sharesinbox.MemoryIncomingShareRepo,
	partyRepo identity.PartyRepo,
) (*incoming.Handler, string) {
	t.Helper()
	return newTestHandler(repo, partyRepo), "sender.com"
}
