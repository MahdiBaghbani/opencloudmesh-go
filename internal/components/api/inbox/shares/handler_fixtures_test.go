package shares_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

const (
	userAID = "user-a-uuid"
	userBID = "user-b-uuid"
)

func currentUserFunc(user *identity.User) func(context.Context) (*identity.User, error) {
	return func(ctx context.Context) (*identity.User, error) {
		if user == nil {
			return nil, fmt.Errorf("no authenticated user in context")
		}

		return user, nil
	}
}

// newTestRouter mounts the inbox shares handler; nil accessClient/cfg suffice for list/accept/decline.
func newTestRouter(repo sharesinbox.IncomingShareRepo, user *identity.User) http.Handler {
	h := inboxshares.NewHandler(repo, nil, currentUserFunc(user), testLogger)
	r := chi.NewRouter()
	r.Route("/inbox/shares", func(r chi.Router) {
		r.Get("/", h.HandleList)
		r.Get("/{shareId}", h.HandleGetDetail)
		r.Post("/{shareId}/accept", h.HandleAccept)
		r.Post("/{shareId}/decline", h.HandleDecline)
	})

	return r
}

func createShareForUser(repo *sharesinbox.MemoryIncomingShareRepo, recipientUserID, providerID, senderHost string) *sharesinbox.IncomingShare {
	share := &sharesinbox.IncomingShare{
		ProviderID:      providerID,
		SenderHost:      senderHost,
		ShareWith:       recipientUserID + "@example.com",
		RecipientUserID: recipientUserID,
		Status:          sharesinbox.ShareStatusPending,
		ResourceType:    "file",
		Name:            "test-share-" + providerID,
		Owner:           "owner@sender.example.com",
		Sender:          "sender@sender.example.com",
		ShareType:       "user",
	}
	repo.Create(context.Background(), share) //nolint:errcheck // test fixture seed without testing.T

	return share
}
