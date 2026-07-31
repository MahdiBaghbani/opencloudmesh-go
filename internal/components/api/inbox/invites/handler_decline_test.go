// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package invites_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

// failingDeleteRepo wraps the memory repo and fails DeleteForRecipientUserID
// to exercise the decline persistence-failure path.
type failingDeleteRepo struct {
	*invitesincoming.MemoryIncomingInviteRepo
}

func (r *failingDeleteRepo) DeleteForRecipientUserID(_ context.Context, _ string, _ string) error {
	return errors.New("simulated delete failure")
}

func TestHandleDecline_Success(t *testing.T) {
	repo := invitesincoming.NewMemoryIncomingInviteRepo()
	invite := createInviteForUser(t, repo, userAID, "decline-token", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/"+invite.ID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	_, err := repo.GetByIDForRecipientUserID(context.Background(), invite.ID, userAID)
	if err == nil {
		t.Error("expected invite to be deleted after decline")
	}
}

func TestHandleDecline_CrossUserReturns404(t *testing.T) {
	repo := invitesincoming.NewMemoryIncomingInviteRepo()
	invite := createInviteForUser(t, repo, userAID, "decline-cross-token", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(t, repo, userB)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/"+invite.ID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user decline, got %d", w.Code)
	}
}

func TestHandleDecline_Unauthenticated(t *testing.T) {
	repo := invitesincoming.NewMemoryIncomingInviteRepo()
	router := newTestRouter(t, repo, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/some-id/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestHandleDecline_PersistFailureReturns5xx verifies a local delete failure
// surfaces as 5xx instead of a silent 200 (C3).
func TestHandleDecline_PersistFailureReturns5xx(t *testing.T) {
	mem := invitesincoming.NewMemoryIncomingInviteRepo()
	invite := createInviteForUser(t, mem, userAID, "decline-fail-token", "sender.example.com")

	repo := &failingDeleteRepo{mem}
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/"+invite.ID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on delete failure, got %d: %s", w.Code, w.Body.String())
	}

	stored, err := mem.GetByIDForRecipientUserID(context.Background(), invite.ID, userAID)
	if err != nil {
		t.Fatalf("expected invite to remain after failed decline: %v", err)
	}

	if stored.Status != invites.InviteStatusPending {
		t.Errorf("expected invite to remain pending, got %s", stored.Status)
	}
}
