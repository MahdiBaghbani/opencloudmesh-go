// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
)

func TestHandleAccept_Success(t *testing.T) {
	runShareStatusTransition(t, "accept", "prov-accept", shares.ShareStatusAccepted)
}

func TestHandleAccept_CrossUserReturns404(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createShareForUser(t, repo, userAID, "prov-cross", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(repo, userB)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user accept, got %d", w.Code)
	}
}

func TestHandleAccept_NonexistentShareReturns404(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingShares
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/nonexistent-id/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleAccept_IdempotentForAlreadyAccepted(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createShareForUser(t, repo, userAID, "prov-idem", "sender.example.com")

	if err := repo.UpdateStatusForRecipientUserID(context.Background(), share.ShareID, userAID, shares.ShareStatusAccepted); err != nil {
		t.Fatalf("UpdateStatusForRecipientUserID: %v", err)
	}

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for idempotent accept, got %d", w.Code)
	}
}

func TestHandleAccept_ConflictForDeclinedShare(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createShareForUser(t, repo, userAID, "prov-declined", "sender.example.com")

	if err := repo.UpdateStatusForRecipientUserID(context.Background(), share.ShareID, userAID, shares.ShareStatusDeclined); err != nil {
		t.Fatalf("UpdateStatusForRecipientUserID: %v", err)
	}

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for accepting a declined share, got %d", w.Code)
	}
}

func TestHandleAccept_Unauthenticated(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingShares
	router := newTestRouter(repo, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/some-id/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
