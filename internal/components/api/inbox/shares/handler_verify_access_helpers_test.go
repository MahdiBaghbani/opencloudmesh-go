package shares_test

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
)

type mockAccessor struct {
	accessFn func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error)
}

func (m *mockAccessor) Access(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
	return m.accessFn(ctx, opts)
}

func newTestRouterWithAccess(
	repo sharesinbox.IncomingShareRepo,
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
	repo *sharesinbox.MemoryIncomingShareRepo,
	recipientUserID, providerID, senderHost, name string,
) *sharesinbox.IncomingShare {
	share := &sharesinbox.IncomingShare{
		ProviderID:      providerID,
		SenderHost:      senderHost,
		ShareWith:       recipientUserID + "@example.com",
		RecipientUserID: recipientUserID,
		Status:          sharesinbox.ShareStatusAccepted,
		ResourceType:    "file",
		Name:            name,
		Owner:           "owner@sender.example.com",
		Sender:          "sender@sender.example.com",
		ShareType:       "user",
		Permissions:     []string{"read"},
		WebDAVID:        "webdav-id-" + providerID,
		SharedSecret:    "secret-" + providerID,
	}
	repo.Create(context.Background(), share)

	return share
}

func createAcceptedWebappShareForUser(
	repo *sharesinbox.MemoryIncomingShareRepo,
	recipientUserID, providerID, senderHost, name string,
) *sharesinbox.IncomingShare {
	share := &sharesinbox.IncomingShare{
		ProviderID:        providerID,
		SenderHost:        senderHost,
		ShareWith:         recipientUserID + "@example.com",
		RecipientUserID:   recipientUserID,
		Status:            sharesinbox.ShareStatusAccepted,
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
	repo.Create(context.Background(), share)

	return share
}
