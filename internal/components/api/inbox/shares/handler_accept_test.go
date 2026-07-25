package shares_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
)

func TestHandleAccept_Success(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-accept", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated, _ := repo.GetByIDForRecipientUserID(context.Background(), share.ShareID, userAID)
	if updated.Status != sharesinbox.ShareStatusAccepted {
		t.Errorf("expected status %s, got %s", sharesinbox.ShareStatusAccepted, updated.Status)
	}
}

func TestHandleAccept_CrossUserReturns404(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-cross", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(repo, userB)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user accept, got %d", w.Code)
	}
}

func TestHandleAccept_NonexistentShareReturns404(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/nonexistent-id/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleAccept_IdempotentForAlreadyAccepted(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-idem", "sender.example.com")

	repo.UpdateStatusForRecipientUserID(context.Background(), share.ShareID, userAID, sharesinbox.ShareStatusAccepted)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for idempotent accept, got %d", w.Code)
	}
}

func TestHandleAccept_ConflictForDeclinedShare(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-declined", "sender.example.com")

	repo.UpdateStatusForRecipientUserID(context.Background(), share.ShareID, userAID, sharesinbox.ShareStatusDeclined)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for accepting a declined share, got %d", w.Code)
	}
}

func TestHandleAccept_Unauthenticated(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	router := newTestRouter(repo, nil)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/some-id/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
