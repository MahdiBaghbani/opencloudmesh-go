// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package invites_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	inboxinvites "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestHandleImport_Success(t *testing.T) {
	repo := invitesincoming.NewMemoryIncomingInviteRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	inviteStr := buildInviteString("import-token-1")
	body := fmt.Sprintf(`{"inviteString":"%s"}`, inviteStr)
	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxinvites.InviteImportResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.SenderFQDN != "remote.example.com" {
		t.Errorf("expected senderFqdn remote.example.com, got %s", resp.SenderFQDN)
	}

	if resp.Status != invites.InviteStatusPending {
		t.Errorf("expected status pending, got %s", resp.Status)
	}

	respBody := w.Body.String()
	if strings.Contains(respBody, "import-token-1") {
		t.Error("response contains token -- must not be leaked")
	}
}

func TestHandleImport_Idempotent(t *testing.T) {
	repo := invitesincoming.NewMemoryIncomingInviteRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	inviteStr := buildInviteString("idem-token")
	body := fmt.Sprintf(`{"inviteString":"%s"}`, inviteStr)

	req1 := httptest.NewRequest(http.MethodPost, "/inbox/invites/import", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")

	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	if w1.Code != http.StatusCreated {
		t.Fatalf("first import: expected 201, got %d", w1.Code)
	}

	var resp1 inboxinvites.InviteImportResponse
	if err := json.Unmarshal(w1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/inbox/invites/import", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")

	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("idempotent import: expected 200, got %d", w2.Code)
	}

	var resp2 inboxinvites.InviteImportResponse
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if resp1.ID != resp2.ID {
		t.Errorf("idempotent import should return same ID: got %s vs %s", resp1.ID, resp2.ID)
	}
}

func TestHandleImport_InvalidInviteString(t *testing.T) {
	repo := invitesincoming.NewMemoryIncomingInviteRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	body := `{"inviteString":"not-valid-base64!!!"}`
	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid invite string, got %d", w.Code)
	}
}

func TestHandleImport_MissingInviteString(t *testing.T) {
	repo := invitesincoming.NewMemoryIncomingInviteRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing inviteString, got %d", w.Code)
	}
}

func TestHandleImport_Unauthenticated(t *testing.T) {
	repo := invitesincoming.NewMemoryIncomingInviteRepo()
	router := newTestRouter(t, repo, nil)

	inviteStr := buildInviteString("token")
	body := fmt.Sprintf(`{"inviteString":"%s"}`, inviteStr)
	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleImport_DifferentUsersCanImportSameToken(t *testing.T) {
	repo := invitesincoming.NewMemoryIncomingInviteRepo()
	inviteStr := buildInviteString("shared-token")
	body := fmt.Sprintf(`{"inviteString":"%s"}`, inviteStr)

	userA := &identity.User{ID: userAID, Username: "alice"}
	routerA := newTestRouter(t, repo, userA)
	req1 := httptest.NewRequest(http.MethodPost, "/inbox/invites/import", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")

	w1 := httptest.NewRecorder()
	routerA.ServeHTTP(w1, req1)

	if w1.Code != http.StatusCreated {
		t.Fatalf("user A import: expected 201, got %d", w1.Code)
	}

	userB := &identity.User{ID: userBID, Username: "bob"}
	routerB := newTestRouter(t, repo, userB)
	req2 := httptest.NewRequest(http.MethodPost, "/inbox/invites/import", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")

	w2 := httptest.NewRecorder()
	routerB.ServeHTTP(w2, req2)

	if w2.Code != http.StatusCreated {
		t.Fatalf("user B import: expected 201, got %d: %s", w2.Code, w2.Body.String())
	}

	invitesA, err := repo.ListByRecipientUserID(context.Background(), userAID)
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	invitesB, err := repo.ListByRecipientUserID(context.Background(), userBID)
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	if len(invitesA) != 1 {
		t.Errorf("expected 1 invite for user A, got %d", len(invitesA))
	}

	if len(invitesB) != 1 {
		t.Errorf("expected 1 invite for user B, got %d", len(invitesB))
	}
}
