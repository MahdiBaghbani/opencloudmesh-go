// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/go-chi/chi/v5"

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

const (
	userAID = "user-a-uuid"
	userBID = "user-b-uuid"
)

func currentUserFunc(user *identity.User) func(context.Context) (*identity.User, error) {
	return func(_ context.Context) (*identity.User, error) {
		if user == nil {
			return nil, errors.New("no authenticated user in context")
		}

		return user, nil
	}
}

// newTestRouter mounts the inbox shares handler; nil accessClient/cfg suffice for list/accept/decline.
func newTestRouter(repo sharesincoming.IncomingShareRepo, user *identity.User) http.Handler {
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

func createShareForUser(t *testing.T, repo sharesincoming.IncomingShareRepo, recipientUserID, providerID, senderHost string) *sharesincoming.IncomingShare { //nolint:unparam // test fixture helper: senderHost kept for fixture signature uniformity; all current callers pass "sender.example.com"
	t.Helper()

	share := &sharesincoming.IncomingShare{
		ProviderID:      providerID,
		SenderHost:      senderHost,
		ShareWith:       recipientUserID + "@example.com",
		RecipientUserID: recipientUserID,
		Status:          shares.ShareStatusPending,
		ResourceType:    "file",
		Name:            "test-share-" + providerID,
		Owner:           "owner@sender.example.com",
		Sender:          "sender@sender.example.com",
		ShareType:       "user",
	}
	if err := repo.Create(context.Background(), share); err != nil {
		t.Fatal(err)
	}

	return share
}

// runShareStatusTransition posts the given accept/decline action for a fresh
// share and asserts a 200 response and the resulting stored status.
func runShareStatusTransition(t *testing.T, action, providerID string, want shares.ShareStatus) {
	t.Helper()

	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createShareForUser(t, repo, userAID, providerID, "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+share.ShareID+"/"+action, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated, err := repo.GetByIDForRecipientUserID(context.Background(), share.ShareID, userAID)
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	if updated.Status != want {
		t.Errorf("expected status %s, got %s", want, updated.Status)
	}
}
