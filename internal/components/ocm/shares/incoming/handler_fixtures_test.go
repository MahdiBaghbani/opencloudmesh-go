// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func setupTestPartyRepo(t *testing.T) identity.PartyRepo {
	t.Helper()

	repo := identity.NewMemoryPartyRepo()
	ctx := context.Background()

	if err := repo.Create(ctx, &identity.User{
		ID:          "user-a-uuid",
		Username:    "alice",
		Email:       "alice@example.org",
		DisplayName: "Alice A",
	}); err != nil {
		t.Fatal(err)
	}

	if err := repo.Create(ctx, &identity.User{
		ID:          "user-b-uuid",
		Username:    "bob",
		Email:       "bob@example.org",
		DisplayName: "Bob B",
	}); err != nil {
		t.Fatal(err)
	}

	return repo
}

// newTestHandler creates a handler wired for testing against localhost:9200 (https).
// Must-invite enforcement is off by default in tests to exercise legacy behavior;
// gate tests use newTestHandlerWithInvites.
func newTestHandler(repo incoming.IncomingShareRepo, partyRepo identity.PartyRepo) *incoming.Handler {
	return newTestHandlerWithResolver(repo, partyRepo, nil)
}

func newTestHandlerWithResolver(
	repo incoming.IncomingShareRepo,
	partyRepo identity.PartyRepo,
	resolver *policy.PeerMappingResolver,
) *incoming.Handler {
	return incoming.NewHandler(
		repo,
		partyRepo,
		nil,   // no policy engine
		nil,   // no incoming invite repo
		nil,   // no outgoing invite repo
		false, // must-invite enforcement off
		"localhost:9200",
		"https",
		resolver,
	)
}

// newTestHandlerWithInvites creates a handler with invite repositories and an
// explicit must-invite enforcement flag for gate tests.
func newTestHandlerWithInvites(
	repo incoming.IncomingShareRepo,
	partyRepo identity.PartyRepo,
	incomingInvites invitesincoming.IncomingInviteRepo,
	outgoingInvites invitesoutgoing.OutgoingInviteRepo,
	enforced bool,
) *incoming.Handler {
	return incoming.NewHandler(
		repo,
		partyRepo,
		nil, // no policy engine
		incomingInvites,
		outgoingInvites,
		enforced,
		"localhost:9200",
		"https",
		nil,
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
	repo incoming.IncomingShareRepo,
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
