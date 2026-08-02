// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package accepted_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// assertEmptyFieldInviteAccepted drives one empty-field acceptance case: a
// local user is created, their pending invite is accepted with body, and the
// handler must return 200.
func assertEmptyFieldInviteAccepted(t *testing.T, localUser *identity.User, token, body, fieldLabel string) {
	t.Helper()

	repo := tsrepos.OpenMemory(t).OutgoingInvites
	partyRepo := identity.NewMemoryPartyRepo()

	if err := partyRepo.Create(context.Background(), localUser); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := newTestHandler(repo, partyRepo)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:           token,
		ProviderFQDN:    testProvider,
		CreatedByUserID: localUser.ID,
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	w := postInviteAccepted(handler, body)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (empty %s allowed), got %d: %s", fieldLabel, w.Code, w.Body.String())
	}
}

func TestHandleInviteAccepted_EmptyEmailAllowed(t *testing.T) {
	assertEmptyFieldInviteAccepted(
		t,
		&identity.User{ID: "user-empty-email", Username: "empty-email-user", Email: ""},
		"empty-email-token",
		`{"recipientProvider":"other.com","token":"empty-email-token","userID":"u@host","email":"","name":"n"}`,
		"email",
	)
}

func TestHandleInviteAccepted_EmptyNameAllowed(t *testing.T) {
	assertEmptyFieldInviteAccepted(
		t,
		&identity.User{ID: "user-empty-name", Username: "empty-name-user", DisplayName: ""},
		"empty-name-token",
		`{"recipientProvider":"other.com","token":"empty-name-token","userID":"u@host","email":"e","name":""}`,
		"name",
	)
}
func TestHandleInviteAccepted_Success_ReturnsLocalUserIdentity(t *testing.T) {
	repo := tsrepos.OpenMemory(t).OutgoingInvites
	partyRepo := identity.NewMemoryPartyRepo()

	localUser := &identity.User{
		ID:          "user-uuid-123",
		Username:    "alice",
		Email:       "alice@example.org",
		DisplayName: "Alice A",
	}
	if err := partyRepo.Create(context.Background(), localUser); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := newTestHandler(repo, partyRepo)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:           "valid-token",
		ProviderFQDN:    testProvider,
		CreatedByUserID: localUser.ID,
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	w := postInviteAccepted(handler, `{"token":"valid-token","recipientProvider":"other.com","userID":"remote-user@other.com","email":"remote@other.com","name":"Remote User"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.InviteAcceptedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	expectedUserID := address.EncodeFederatedOpaqueID(localUser.ID, testProvider)
	if resp.UserID != expectedUserID {
		t.Errorf("userID = %q, want %q (local user, not remote echo)", resp.UserID, expectedUserID)
	}

	if resp.Email != "alice@example.org" {
		t.Errorf("email = %q, want %q (local user email)", resp.Email, "alice@example.org")
	}

	if resp.Name != "Alice A" {
		t.Errorf("name = %q, want %q (local user display name)", resp.Name, "Alice A")
	}

	updated, err := repo.GetByToken(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	if updated.Status != invites.InviteStatusAccepted {
		t.Errorf("expected status %s, got %s", invites.InviteStatusAccepted, updated.Status)
	}
}

func TestHandleInviteAccepted_Success_EmptyEmailAndName(t *testing.T) {
	repo := tsrepos.OpenMemory(t).OutgoingInvites
	partyRepo := identity.NewMemoryPartyRepo()

	localUser := &identity.User{
		ID:       "user-uuid-456",
		Username: "bob",
	}
	if err := partyRepo.Create(context.Background(), localUser); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := newTestHandler(repo, partyRepo)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:           "valid-token",
		ProviderFQDN:    testProvider,
		CreatedByUserID: localUser.ID,
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	w := postInviteAccepted(handler, `{"token":"valid-token","recipientProvider":"other.com","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.InviteAcceptedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.Email != "" {
		t.Errorf("email = %q, want empty string", resp.Email)
	}

	if resp.Name != "" {
		t.Errorf("name = %q, want empty string", resp.Name)
	}

	updated, err := repo.GetByToken(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	if updated.Status != invites.InviteStatusAccepted {
		t.Errorf("expected status %s, got %s", invites.InviteStatusAccepted, updated.Status)
	}
}
