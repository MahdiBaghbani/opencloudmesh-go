package shares_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
)

func TestHandleDecline_Success(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-decline", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated, err := repo.GetByIDForRecipientUserID(context.Background(), share.ShareID, userAID)
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	if updated.Status != shares.ShareStatusDeclined {
		t.Errorf("expected status %s, got %s", shares.ShareStatusDeclined, updated.Status)
	}
}

func TestHandleDecline_CrossUserReturns404(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
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
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-acc-dec", "sender.example.com")

	if err := repo.UpdateStatusForRecipientUserID(context.Background(), share.ShareID, userAID, shares.ShareStatusAccepted); err != nil {
		t.Fatalf("UpdateStatusForRecipientUserID: %v", err)
	}

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for declining an accepted share, got %d", w.Code)
	}
}
