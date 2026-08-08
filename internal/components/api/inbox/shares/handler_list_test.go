// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
)

func TestHandleList_ReturnsOnlyCurrentUserShares(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	shareA := createShareForUser(t, repo, userAID, "prov-a1", "sender.example.com")
	createShareForUser(t, repo, userBID, "prov-b1", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/inbox/shares/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.InboxListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.Shares) != 1 {
		t.Fatalf("expected 1 share for user A, got %d", len(resp.Shares))
	}

	if resp.Shares[0].ShareID != shareA.ShareID {
		t.Errorf("expected share %s, got %s", shareA.ShareID, resp.Shares[0].ShareID)
	}
}

func TestHandleList_EmptyForUserWithNoShares(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	createShareForUser(t, repo, userAID, "prov-a1", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(repo, userB)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/inbox/shares/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp inboxshares.InboxListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(resp.Shares) != 0 {
		t.Errorf("expected empty list for user B, got %d shares", len(resp.Shares))
	}
}

func TestHandleList_Unauthenticated(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	router := newTestRouter(repo, nil) // nil user = unauthenticated

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/inbox/shares/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
func TestHandleList_DoesNotLeakSensitiveFields(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares

	share := &sharesincoming.IncomingShare{
		ProviderID:           "prov-sensitive",
		SenderHost:           "sender.example.com",
		ShareWith:            userAID + "@example.com",
		RecipientUserID:      userAID,
		RecipientDisplayName: "Alice A",
		SharedSecret:         "super-secret-token",
		Status:               shares.ShareStatusPending,
		ResourceType:         "file",
		Name:                 "test-share",
		Owner:                "owner@sender.example.com",
		Sender:               "sender@sender.example.com",
		ShareType:            "user",
	}
	if err := repo.Create(context.Background(), share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/inbox/shares/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	body := w.Body.String()

	if strings.Contains(body, "super-secret-token") {
		t.Error("response contains SharedSecret -- must not be leaked")
	}

	if strings.Contains(body, "recipientUserID") || strings.Contains(body, "RecipientUserID") {
		t.Error("response contains RecipientUserID field name -- must not be leaked")
	}
}
