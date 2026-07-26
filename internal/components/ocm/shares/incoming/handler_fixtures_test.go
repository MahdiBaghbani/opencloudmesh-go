package incoming_test

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

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

func newTestHandlerWithResolver(
	repo *sharesinbox.MemoryIncomingShareRepo,
	partyRepo identity.PartyRepo,
	resolver *policy.PeerMappingResolver,
) *incoming.Handler {
	return incoming.NewHandler(
		repo,
		partyRepo,
		nil, // no policy engine
		"localhost:9200",
		"https",
		resolver,
	)
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

// validWebappShareBody builds a valid multi+webapp share request (no webdav
// arm) targeting the given recipient and using ownerHost for owner+sender.
func validWebappShareBody(shareWith, ownerHost, providerID string) string {
	return `{
		"shareWith": "` + shareWith + `",
		"name": "webapp-resource",
		"providerId": "` + providerID + `",
		"owner": "owner@` + ownerHost + `",
		"sender": "sender@` + ownerHost + `",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "multi",
			"webapp": {
				"uri": "https://` + ownerHost + `/apps/files/abc",
				"targets": ["blank"],
				"permissions": ["view", "read"],
				"requirements": ["must-exchange-token"],
				"sharedSecret": "secret123"
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

func ptrBool(v bool) *bool {
	return &v
}

func peerMappingConfigWithInstance(host string) *config.PeerMappingConfig {
	return &config.PeerMappingConfig{
		Platform: map[string]config.PeerPlatformOverlay{
			"platform-a": {
				Instance: map[string]config.PeerMappingInstanceOverlay{
					host: {
						RequiresTokenExchangeRequirement: ptrBool(false),
					},
				},
			},
		},
	}
}
