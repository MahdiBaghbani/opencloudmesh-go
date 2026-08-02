// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package invites_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	inboxinvites "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestHandleList_ReturnsOnlyCurrentUserInvites(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites
	invA := createInviteForUser(t, repo, userAID, "token-a", "sender-a.example.com")
	createInviteForUser(t, repo, userBID, "token-b", "sender-b.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/inbox/invites/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxinvites.InboxListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.Invites) != 1 {
		t.Fatalf("expected 1 invite for user A, got %d", len(resp.Invites))
	}

	if resp.Invites[0].ID != invA.ID {
		t.Errorf("expected invite %s, got %s", invA.ID, resp.Invites[0].ID)
	}
}

func TestHandleList_EmptyForUserWithNoInvites(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites
	createInviteForUser(t, repo, userAID, "token-a", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(t, repo, userB)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/inbox/invites/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp inboxinvites.InboxListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(resp.Invites) != 0 {
		t.Errorf("expected empty list for user B, got %d invites", len(resp.Invites))
	}
}

func TestHandleList_Unauthenticated(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites
	router := newTestRouter(t, repo, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/inbox/invites/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleList_DoesNotLeakToken(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites
	createInviteForUser(t, repo, userAID, "super-secret-token-123", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/inbox/invites/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, "super-secret-token-123") {
		t.Error("response contains invite token -- must not be leaked")
	}
}
