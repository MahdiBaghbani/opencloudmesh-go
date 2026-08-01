// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
)

type mockAccessor struct {
	accessFn func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error)
}

func (m *mockAccessor) Access(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
	return m.accessFn(ctx, opts)
}

func newTestRouterWithAccess(
	repo sharesincoming.IncomingShareRepo,
	ac access.RemoteAccessor,
	user *identity.User,
) http.Handler {
	h := inboxshares.NewHandler(repo, ac, currentUserFunc(user), testLogger)
	r := chi.NewRouter()
	r.Route("/inbox/shares", func(r chi.Router) {
		r.Get("/", h.HandleList)
		r.Get("/{shareId}", h.HandleGetDetail)
		r.Post("/{shareId}/accept", h.HandleAccept)
		r.Post("/{shareId}/decline", h.HandleDecline)
		r.Post("/{shareId}/verify-access", h.HandleVerifyAccess)
	})

	return r
}

func createAcceptedShareForUser(
	t *testing.T,
	repo sharesincoming.IncomingShareRepo,
	providerID, senderHost, name string, //nolint:unparam // test fixture helper: senderHost kept for fixture signature uniformity; all current callers pass "sender.example.com"
) *sharesincoming.IncomingShare {
	t.Helper()

	share := &sharesincoming.IncomingShare{
		ProviderID:      providerID,
		SenderHost:      senderHost,
		ShareWith:       userAID + "@example.com",
		RecipientUserID: userAID,
		Status:          shares.ShareStatusAccepted,
		ResourceType:    "file",
		Name:            name,
		Owner:           "owner@sender.example.com",
		Sender:          "sender@sender.example.com",
		ShareType:       "user",
		Permissions:     []string{"read"},
		WebDAVID:        "webdav-id-" + providerID,
		SharedSecret:    "secret-" + providerID,
	}
	if err := repo.Create(context.Background(), share); err != nil {
		t.Fatal(err)
	}

	return share
}

func createAcceptedWebappShareForUser(
	t *testing.T,
	repo sharesincoming.IncomingShareRepo,
	recipientUserID, providerID, senderHost, name string,
) *sharesincoming.IncomingShare {
	t.Helper()

	share := &sharesincoming.IncomingShare{
		ProviderID:        providerID,
		SenderHost:        senderHost,
		ShareWith:         recipientUserID + "@example.com",
		RecipientUserID:   recipientUserID,
		Status:            shares.ShareStatusAccepted,
		ResourceType:      "file",
		Name:              name,
		Owner:             "owner@sender.example.com",
		Sender:            "sender@sender.example.com",
		ShareType:         "user",
		Permissions:       []string{"read"},
		WebDAVID:          "webdav-id-" + providerID,
		SharedSecret:      "secret-" + providerID,
		Requirements:      []string{"must-exchange-token"},
		ProtocolName:      "webapp",
		WebappURI:         "https://app.sender.example.com/launch?share=" + providerID,
		WebappTargets:     []string{"blank", "_self"},
		WebappPermissions: []string{"view", "share"},
	}
	if err := repo.Create(context.Background(), share); err != nil {
		t.Fatal(err)
	}

	return share
}
