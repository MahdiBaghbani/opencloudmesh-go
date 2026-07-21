package incoming_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

const (
	testProvider = "example.com"
	testScheme   = "https"
)

func newTestHandler(repo invitesoutgoing.OutgoingInviteRepo, partyRepo identity.PartyRepo) *incoming.Handler {
	if partyRepo == nil {
		partyRepo = identity.NewMemoryPartyRepo()
	}
	return incoming.NewHandler(repo, partyRepo, nil, testProvider, testScheme, testLogger)
}

func postInviteAccepted(handler *incoming.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.HandleInviteAccepted(w, req)
	return w
}

func decodeOCMError(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	return resp["message"]
}

func validAcceptedBody(token string) string {
	return `{"recipientProvider":"other.com","token":"` + token + `","userID":"u@host","email":"remote@other.com","name":"Remote User"}`
}

func TestHandleInviteAccepted_RecipientProviderRequired(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"","token":"t","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if msg := decodeOCMError(t, w); msg != "RECIPIENT_PROVIDER_REQUIRED" {
		t.Errorf("expected RECIPIENT_PROVIDER_REQUIRED, got %q", msg)
	}
}

func TestHandleInviteAccepted_InvalidRecipientProvider(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"https://other.com","token":"t","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if msg := decodeOCMError(t, w); msg != "INVALID_RECIPIENT_PROVIDER" {
		t.Errorf("expected INVALID_RECIPIENT_PROVIDER, got %q", msg)
	}
}

func TestHandleInviteAccepted_TokenRequired(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if msg := decodeOCMError(t, w); msg != "TOKEN_REQUIRED" {
		t.Errorf("expected TOKEN_REQUIRED, got %q", msg)
	}
}

func TestHandleInviteAccepted_UserIDRequired(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"t","userID":"","email":"e","name":"n"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if msg := decodeOCMError(t, w); msg != "USERID_REQUIRED" {
		t.Errorf("expected USERID_REQUIRED, got %q", msg)
	}
}

func TestHandleInviteAccepted_EmailKeyMissing(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"t","userID":"u@host","name":"n"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if msg := decodeOCMError(t, w); msg != "EMAIL_REQUIRED" {
		t.Errorf("expected EMAIL_REQUIRED, got %q", msg)
	}
}

func TestHandleInviteAccepted_NameKeyMissing(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"t","userID":"u@host","email":"e"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if msg := decodeOCMError(t, w); msg != "NAME_REQUIRED" {
		t.Errorf("expected NAME_REQUIRED, got %q", msg)
	}
}

func TestHandleInviteAccepted_EmptyEmailAllowed(t *testing.T) {
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
	repo.Create(context.Background(), invite)

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"empty-email-token","userID":"u@host","email":"","name":"n"}`)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (empty email allowed), got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleInviteAccepted_EmptyNameAllowed(t *testing.T) {
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
	repo.Create(context.Background(), invite)

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"empty-name-token","userID":"u@host","email":"e","name":""}`)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (empty name allowed), got %d: %s", w.Code, w.Body.String())
	}
}

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
	repo.Create(context.Background(), invite)

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
	repo.Create(context.Background(), invite)

	w := postInviteAccepted(handler, validAcceptedBody("accepted-token"))
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	if msg := decodeOCMError(t, w); msg != "INVITE_ALREADY_ACCEPTED" {
		t.Errorf("expected INVITE_ALREADY_ACCEPTED, got %q", msg)
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
	repo.Create(context.Background(), invite)

	body := validAcceptedBody("trust-token")
	req := httptest.NewRequest(http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString(body))
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
	repo.Create(context.Background(), invite)

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
	updated, _ := repo.GetByToken(context.Background(), "valid-token")
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
	repo.Create(context.Background(), invite)

	w := postInviteAccepted(handler, `{"token":"valid-token","recipientProvider":"other.com","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.InviteAcceptedResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Email != "" {
		t.Errorf("email = %q, want empty string", resp.Email)
	}
	if resp.Name != "" {
		t.Errorf("name = %q, want empty string", resp.Name)
	}
	updated, _ := repo.GetByToken(context.Background(), "valid-token")
	if updated.Status != invites.InviteStatusAccepted {
		t.Errorf("expected status %s, got %s", invites.InviteStatusAccepted, updated.Status)
	}
}

type outgoingRepoSpy struct {
	*invitesoutgoing.MemoryOutgoingInviteRepo
	updateStatusCalled bool
}

func (s *outgoingRepoSpy) UpdateStatus(ctx context.Context, id string, status invites.InviteStatus, acceptedBy string) error {
	s.updateStatusCalled = true
	return s.MemoryOutgoingInviteRepo.UpdateStatus(ctx, id, status, acceptedBy)
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
	repo.Create(context.Background(), invite)

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
	updated, _ := memoryRepo.GetByToken(context.Background(), "party-get-fail-token")
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
	repo.Create(context.Background(), invite)

	w := postInviteAccepted(handler, `{"token":"empty-creator-token","recipientProvider":"other.com","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for empty creator, got %d: %s", w.Code, w.Body.String())
	}
	if msg := decodeOCMError(t, w); msg != "INVITER_IDENTITY_UNAVAILABLE" {
		t.Errorf("expected INVITER_IDENTITY_UNAVAILABLE, got %q", msg)
	}
	updated, _ := repo.GetByToken(context.Background(), "empty-creator-token")
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
	handler := incoming.NewHandler(repo, identity.NewMemoryPartyRepo(), nil, testProvider, "", testLogger)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:        "empty-origin-token",
		ProviderFQDN: testProvider,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Status:       invites.InviteStatusPending,
	}
	repo.Create(context.Background(), invite)

	body := `{"recipientProvider":"other.com:443","token":"empty-origin-token","userID":"u@host","email":"e","name":"n"}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString(body))
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

func TestHandleInviteAccepted_StrictContentType(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	req := httptest.NewRequest(http.MethodPost, "/ocm/invite-accepted",
		bytes.NewBufferString("token=abc&recipientProvider=other.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.HandleInviteAccepted(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", w.Code)
	}
}

func TestHandleInviteAccepted_ResponseFieldsAlwaysPresent(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	partyRepo := identity.NewMemoryPartyRepo()

	localUser := &identity.User{
		ID:       "user-uuid-789",
		Username: "charlie",
	}
	partyRepo.Create(context.Background(), localUser)

	handler := newTestHandler(repo, partyRepo)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:           "field-test-token",
		ProviderFQDN:    testProvider,
		CreatedByUserID: localUser.ID,
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	repo.Create(context.Background(), invite)

	w := postInviteAccepted(handler, `{"token":"field-test-token","recipientProvider":"other.com","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Parse as raw JSON to verify email and name fields are present (not omitted)
	var raw map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("failed to parse raw JSON: %v", err)
	}
	for _, field := range []string{"userID", "email", "name"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("field %q missing from response", field)
		}
	}
}
