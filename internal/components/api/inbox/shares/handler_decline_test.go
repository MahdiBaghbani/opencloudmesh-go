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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
)

func TestHandleDecline_Success(t *testing.T) {
	runShareStatusTransition(t, "decline", "prov-decline", shares.ShareStatusDeclined)
}

func TestHandleDecline_CrossUserReturns404(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createShareForUser(t, repo, userAID, "prov-cross-dec", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(repo, userB)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+share.ShareID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user decline, got %d", w.Code)
	}
}

func TestHandleDecline_ConflictForAcceptedShare(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createShareForUser(t, repo, userAID, "prov-acc-dec", "sender.example.com")

	if err := repo.UpdateStatusForRecipientUserID(context.Background(), share.ShareID, userAID, shares.ShareStatusAccepted); err != nil {
		t.Fatalf("UpdateStatusForRecipientUserID: %v", err)
	}

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+share.ShareID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for declining an accepted share, got %d", w.Code)
	}
}
