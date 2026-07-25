package invites_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestHandleDecline_Success(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	invite := createInviteForUser(repo, userAID, "decline-token", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/"+invite.ID+"/decline", nil)
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
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	invite := createInviteForUser(repo, userAID, "decline-cross-token", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(t, repo, userB)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/"+invite.ID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user decline, got %d", w.Code)
	}
}

func TestHandleDecline_Unauthenticated(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	router := newTestRouter(t, repo, nil)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/some-id/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
