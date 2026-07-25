package shares_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
)

func TestHandleDecline_Success(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-decline", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated, _ := repo.GetByIDForRecipientUserID(context.Background(), share.ShareID, userAID)
	if updated.Status != sharesinbox.ShareStatusDeclined {
		t.Errorf("expected status %s, got %s", sharesinbox.ShareStatusDeclined, updated.Status)
	}
}

func TestHandleDecline_CrossUserReturns404(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-cross-dec", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(repo, userB)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user decline, got %d", w.Code)
	}
}

func TestHandleDecline_ConflictForAcceptedShare(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-acc-dec", "sender.example.com")

	repo.UpdateStatusForRecipientUserID(context.Background(), share.ShareID, userAID, sharesinbox.ShareStatusAccepted)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for declining an accepted share, got %d", w.Code)
	}
}
