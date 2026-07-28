package shares_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
)

func TestHandleVerifyAccess_CrossUserReturns404(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, "prov-va-cross", "sender.example.com", "file.txt")

	userB := &identity.User{ID: userBID, Username: "bob"}
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
		t.Fatal("access client should not be called for cross-user request")
		return nil, nil //nolint:nilnil // test: unreachable after t.Fatal; satisfies the mock accessor signature
	}}
	router := newTestRouterWithAccess(repo, ac, userB)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user verify, got %d", w.Code)
	}
}

func TestHandleVerifyAccess_ShareNotAcceptedReturns400(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-va-pending", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
		t.Fatal("access client should not be called for non-accepted share")
		return nil, nil //nolint:nilnil // test: unreachable after t.Fatal; satisfies the mock accessor signature
	}}
	router := newTestRouterWithAccess(repo, ac, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if resp.ReasonCode != "share_not_accepted" {
		t.Errorf("expected reasonCode share_not_accepted, got %s", resp.ReasonCode)
	}
}

func TestHandleVerifyAccess_UnsafePathReturns400(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, "prov-va-unsafe", "sender.example.com", "../etc/passwd")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
		t.Fatal("access client should not be called for unsafe path")
		return nil, nil //nolint:nilnil // test: unreachable after t.Fatal; satisfies the mock accessor signature
	}}
	router := newTestRouterWithAccess(repo, ac, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if resp.ReasonCode != "unsafe_path" {
		t.Errorf("expected reasonCode unsafe_path, got %s", resp.ReasonCode)
	}
}
