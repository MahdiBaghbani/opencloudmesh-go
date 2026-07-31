// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package accepted_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing/accepted"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestHandleInviteAccepted_TokenInvalid(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, validAcceptedBody("nonexistent"))

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (not 404), got %d", w.Code)
	}

	if msg := decodeOCMError(t, w); msg != "TOKEN_INVALID" {
		t.Errorf("expected TOKEN_INVALID, got %q", msg)
	}
}

func TestHandleInviteAccepted_TokenExpired(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:        "expired-token",
		ProviderFQDN: testProvider,
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		Status:       invites.InviteStatusPending,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	w := postInviteAccepted(handler, validAcceptedBody("expired-token"))

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	if msg := decodeOCMError(t, w); msg != "TOKEN_EXPIRED" {
		t.Errorf("expected TOKEN_EXPIRED, got %q", msg)
	}
}

func TestHandleInviteAccepted_AlreadyAccepted_Returns409(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:        "accepted-token",
		ProviderFQDN: testProvider,
		Status:       invites.InviteStatusAccepted,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	w := postInviteAccepted(handler, validAcceptedBody("accepted-token"))
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", w.Code, w.Body.String())
	}

	// Without a resolvable inviter identity the 409 falls back to a plain
	// message body.
	if msg := decodeOCMError(t, w); msg != "INVITE_ALREADY_ACCEPTED" {
		t.Errorf("expected INVITE_ALREADY_ACCEPTED, got %q", msg)
	}
}

func TestHandleInviteAccepted_AlreadyAccepted_Returns409WithIdentityBody(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	partyRepo := identity.NewMemoryPartyRepo()

	localUser := &identity.User{
		ID:          "user-uuid-409",
		Username:    "dave",
		Email:       "dave@example.com",
		DisplayName: "Dave D",
	}
	if err := partyRepo.Create(context.Background(), localUser); err != nil {
		t.Fatalf("Create user: %v", err)
	}

	handler := newTestHandler(repo, partyRepo)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:           "accepted-identity-token",
		ProviderFQDN:    testProvider,
		CreatedByUserID: localUser.ID,
		Status:          invites.InviteStatusAccepted,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	w := postInviteAccepted(handler, validAcceptedBody("accepted-identity-token"))
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}

	// The 409 carries the invite-accepted identity body so an ocmgo receiver
	// can recover the sender identity on retry (idempotent success).
	var resp spec.InviteAcceptedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("expected decodable identity body on 409, got %v: %s", err, w.Body.String())
	}

	expectedUserID := address.EncodeFederatedOpaqueID(localUser.ID, testProvider)
	if resp.UserID != expectedUserID {
		t.Errorf("userID = %q, want %q", resp.UserID, expectedUserID)
	}

	if resp.Email != localUser.Email || resp.Name != localUser.DisplayName {
		t.Errorf("identity mismatch: got email=%q name=%q", resp.Email, resp.Name)
	}
}

func TestHandleInviteAccepted_UntrustedProvider_Returns403(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:        "trust-token",
		ProviderFQDN: testProvider,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Status:       invites.InviteStatusPending,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	body := validAcceptedBody("trust-token")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	peerCtx := context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
		Authority:           "attacker.com",
		AuthorityForCompare: "attacker.com",
		Authenticated:       true,
	})
	req = req.WithContext(peerCtx)

	w := httptest.NewRecorder()
	handler.HandleInviteAccepted(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	if msg := decodeOCMError(t, w); msg != "UNTRUSTED_PROVIDER" {
		t.Errorf("expected UNTRUSTED_PROVIDER, got %q", msg)
	}
}

// TestHandleInviteAccepted_UnnormalizableProvider_FailsClosed verifies the
// unauthenticated path fails closed when the body recipient provider cannot be
// normalized (no raw-provider policy evaluation, no lowercase fallback).
func TestHandleInviteAccepted_UnnormalizableProvider_FailsClosed(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:        "norm-fail-token",
		ProviderFQDN: testProvider,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Status:       invites.InviteStatusPending,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	body := `{"recipientProvider":"bad host","token":"norm-fail-token","userID":"u@host","email":"remote@other.com","name":"Remote User"}`
	w := postInviteAccepted(handler, body)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	if msg := decodeOCMError(t, w); msg != "UNTRUSTED_PROVIDER" {
		t.Errorf("expected UNTRUSTED_PROVIDER, got %q", msg)
	}

	stored, err := repo.GetByToken(context.Background(), "norm-fail-token")
	if err != nil {
		t.Fatalf("GetByToken: %v", err)
	}

	if stored.Status != invites.InviteStatusPending {
		t.Errorf("expected invite to remain pending, got %s", stored.Status)
	}
}

type outgoingRepoSpy struct {
	*invitesoutgoing.MemoryOutgoingInviteRepo

	updateStatusCalled bool
}

func (s *outgoingRepoSpy) UpdateStatus(ctx context.Context, id string, status invites.InviteStatus, acceptance *invitesoutgoing.Acceptance) error {
	s.updateStatusCalled = true
	return s.MemoryOutgoingInviteRepo.UpdateStatus(ctx, id, status, acceptance)
}

type partyRepoGetFail struct {
	failID string
}

func (r *partyRepoGetFail) Create(context.Context, *identity.User) error { return nil }

func (r *partyRepoGetFail) Get(_ context.Context, id string) (*identity.User, error) {
	if id == r.failID {
		return nil, errors.New("party lookup failed")
	}

	return nil, identity.ErrUserNotFound
}

func (r *partyRepoGetFail) GetByUsername(context.Context, string) (*identity.User, error) {
	return nil, identity.ErrUserNotFound
}

func (r *partyRepoGetFail) GetByEmail(context.Context, string) (*identity.User, error) {
	return nil, identity.ErrUserNotFound
}

func (r *partyRepoGetFail) Update(context.Context, *identity.User) error { return nil }

func (r *partyRepoGetFail) Delete(context.Context, string) error { return nil }

func (r *partyRepoGetFail) List(context.Context, string) ([]*identity.User, error) {
	return nil, nil
}

func (r *partyRepoGetFail) DeleteExpired(context.Context) (int, error) { return 0, nil }

func TestHandleInviteAccepted_PartyRepoGetFails_InviterIdentityUnavailable(t *testing.T) {
	memoryRepo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	repo := &outgoingRepoSpy{MemoryOutgoingInviteRepo: memoryRepo}
	creatorID := "missing-creator-user"
	partyRepo := &partyRepoGetFail{failID: creatorID}
	handler := newTestHandler(repo, partyRepo)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:           "party-get-fail-token",
		ProviderFQDN:    testProvider,
		CreatedByUserID: creatorID,
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	w := postInviteAccepted(handler, `{"token":"party-get-fail-token","recipientProvider":"other.com","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for party repo get failure, got %d: %s", w.Code, w.Body.String())
	}

	if msg := decodeOCMError(t, w); msg != "INVITER_IDENTITY_UNAVAILABLE" {
		t.Errorf("expected INVITER_IDENTITY_UNAVAILABLE, got %q", msg)
	}

	if repo.updateStatusCalled {
		t.Error("UpdateStatus should not have been called")
	}

	updated, err := memoryRepo.GetByToken(context.Background(), "party-get-fail-token")
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	if updated.Status != invites.InviteStatusPending {
		t.Errorf("expected status %s (no mutation), got %s", invites.InviteStatusPending, updated.Status)
	}
}

func TestHandleInviteAccepted_EmptyCreator_InviterIdentityUnavailable(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	partyRepo := identity.NewMemoryPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:           "empty-creator-token",
		ProviderFQDN:    testProvider,
		CreatedByUserID: "",
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	w := postInviteAccepted(handler, `{"token":"empty-creator-token","recipientProvider":"other.com","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for empty creator, got %d: %s", w.Code, w.Body.String())
	}

	if msg := decodeOCMError(t, w); msg != "INVITER_IDENTITY_UNAVAILABLE" {
		t.Errorf("expected INVITER_IDENTITY_UNAVAILABLE, got %q", msg)
	}

	updated, err := repo.GetByToken(context.Background(), "empty-creator-token")
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	if updated.Status != invites.InviteStatusPending {
		t.Errorf("expected status %s (no mutation), got %s", invites.InviteStatusPending, updated.Status)
	}
}

// TestHandleInviteAccepted_EmptyPublicOrigin_NoHTTPSDefault proves that an
// empty publicOrigin leaves localScheme empty (not forced to "https"). With an
// empty scheme, hostport.Normalize preserves the explicit :443 port, so the
// recipientProvider "other.com:443" does not collapse to the bare "other.com"
// signature authority and the request is rejected as untrusted. If the scheme
// were forced to "https", :443 would be stripped and the authorities would
// incorrectly match.
func TestHandleInviteAccepted_EmptyPublicOrigin_NoHTTPSDefault(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := accepted.NewHandler(repo, identity.NewMemoryPartyRepo(), nil, testProvider, "")

	invite := &invitesoutgoing.OutgoingInvite{
		Token:        "empty-origin-token",
		ProviderFQDN: testProvider,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Status:       invites.InviteStatusPending,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	body := `{"recipientProvider":"other.com:443","token":"empty-origin-token","userID":"u@host","email":"e","name":"n"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	peerCtx := context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
		Authority:           "other.com",
		AuthorityForCompare: "other.com",
		Authenticated:       true,
	})
	req = req.WithContext(peerCtx)
	w := httptest.NewRecorder()

	handler.HandleInviteAccepted(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (empty scheme keeps :443, so no match), got %d: %s", w.Code, w.Body.String())
	}

	if msg := decodeOCMError(t, w); msg != "UNTRUSTED_PROVIDER" {
		t.Errorf("expected UNTRUSTED_PROVIDER, got %q", msg)
	}
}
