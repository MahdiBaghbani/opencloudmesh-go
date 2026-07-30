package accepted_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestHandleInviteAccepted_EmptyEmailAllowed(t *testing.T) { //nolint:dupl // intentional: parallel empty-field invite tests share setup but assert different optional fields
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	partyRepo := identity.NewMemoryPartyRepo()

	localUser := &identity.User{
		ID:       "user-empty-email",
		Username: "empty-email-user",
		Email:    "",
	}
	if err := partyRepo.Create(context.Background(), localUser); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := newTestHandler(repo, partyRepo)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:           "empty-email-token",
		ProviderFQDN:    testProvider,
		CreatedByUserID: localUser.ID,
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"empty-email-token","userID":"u@host","email":"","name":"n"}`)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (empty email allowed), got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleInviteAccepted_EmptyNameAllowed(t *testing.T) { //nolint:dupl // intentional: parallel empty-field invite tests share setup but assert different optional fields
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	partyRepo := identity.NewMemoryPartyRepo()

	localUser := &identity.User{
		ID:          "user-empty-name",
		Username:    "empty-name-user",
		DisplayName: "",
	}
	if err := partyRepo.Create(context.Background(), localUser); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := newTestHandler(repo, partyRepo)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:           "empty-name-token",
		ProviderFQDN:    testProvider,
		CreatedByUserID: localUser.ID,
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"empty-name-token","userID":"u@host","email":"e","name":""}`)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (empty name allowed), got %d: %s", w.Code, w.Body.String())
	}
}
func TestHandleInviteAccepted_Success_ReturnsLocalUserIdentity(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
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
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
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
