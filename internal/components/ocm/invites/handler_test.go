package invites_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

const (
	testProvider     = "example.com"
	testPublicOrigin = "https://example.com"
)

// newTestHandler creates a handler with repo and optional partyRepo/currentUser.
func newTestHandler(repo *invites.MemoryOutgoingInviteRepo, partyRepo identity.PartyRepo) *invites.Handler {
	return invites.NewHandler(repo, partyRepo, testProvider, testPublicOrigin, nil, testLogger)
}

// newTestHandlerWithCurrentUser creates a handler with a CurrentUser injector for HandleCreateOutgoing tests.
func newTestHandlerWithCurrentUser(repo *invites.MemoryOutgoingInviteRepo, user *identity.User) *invites.Handler {
	currentUser := func(ctx context.Context) (*identity.User, error) {
		return user, nil
	}
	return invites.NewHandler(repo, nil, testProvider, testPublicOrigin, currentUser, testLogger)
}

func postInviteAccepted(handler *invites.Handler, body string) *httptest.ResponseRecorder {
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

// --- HandleInviteAccepted error table tests (F3=A) ---

// validAcceptedBody returns a complete AcceptedInvite JSON body.
// All five spec-required fields are present.
func validAcceptedBody(token string) string {
	return `{"recipientProvider":"other.com","token":"` + token + `","userID":"u@host","email":"remote@other.com","name":"Remote User"}`
}

func TestHandleInviteAccepted_RecipientProviderRequired(t *testing.T) {
	repo := invites.NewMemoryOutgoingInviteRepo()
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
	repo := invites.NewMemoryOutgoingInviteRepo()
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
	repo := invites.NewMemoryOutgoingInviteRepo()
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
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"t","userID":"","email":"e","name":"n"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if msg := decodeOCMError(t, w); msg != "USERID_REQUIRED" {
		t.Errorf("expected USERID_REQUIRED, got %q", msg)
	}
}

func TestHandleInviteAccepted_EmailRequired(t *testing.T) {
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"t","userID":"u@host","email":"","name":"n"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if msg := decodeOCMError(t, w); msg != "EMAIL_REQUIRED" {
		t.Errorf("expected EMAIL_REQUIRED, got %q", msg)
	}
}

func TestHandleInviteAccepted_NameRequired(t *testing.T) {
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"t","userID":"u@host","email":"e","name":""}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if msg := decodeOCMError(t, w); msg != "NAME_REQUIRED" {
		t.Errorf("expected NAME_REQUIRED, got %q", msg)
	}
}

func TestHandleInviteAccepted_TokenInvalid(t *testing.T) {
	repo := invites.NewMemoryOutgoingInviteRepo()
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
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	invite := &invites.OutgoingInvite{
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
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	invite := &invites.OutgoingInvite{
		Token:        "accepted-token",
		ProviderFQDN: testProvider,
		Status:       invites.InviteStatusAccepted,
	}
	repo.Create(context.Background(), invite)

	w := postInviteAccepted(handler, validAcceptedBody("accepted-token"))

	// Spec-mandated: 409, not 200 (fixes old bug)
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	if msg := decodeOCMError(t, w); msg != "INVITE_ALREADY_ACCEPTED" {
		t.Errorf("expected INVITE_ALREADY_ACCEPTED, got %q", msg)
	}
}

func TestHandleInviteAccepted_UntrustedProvider_Returns403(t *testing.T) {
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := newTestHandler(repo, nil)

	invite := &invites.OutgoingInvite{
		Token:        "trust-token",
		ProviderFQDN: testProvider,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Status:       invites.InviteStatusPending,
	}
	repo.Create(context.Background(), invite)

	// Build a request with a mismatched authenticated peer identity
	body := validAcceptedBody("trust-token")
	req := httptest.NewRequest(http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	// Inject a verified peer identity that does NOT match the recipientProvider
	peerCtx := context.WithValue(req.Context(), crypto.PeerIdentityKey, &crypto.PeerIdentity{
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

// --- HandleInviteAccepted success and response tests ---

func TestHandleInviteAccepted_Success_ReturnsLocalUserIdentity(t *testing.T) {
	repo := invites.NewMemoryOutgoingInviteRepo()
	partyRepo := identity.NewMemoryPartyRepo()

	// Create the local inviting user
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

	invite := &invites.OutgoingInvite{
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

	var resp invites.InviteAcceptedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Response must return LOCAL user identity, NOT the remote user's
	expectedUserID := address.FormatOutgoing(localUser.ID, testProvider)
	if resp.UserID != expectedUserID {
		t.Errorf("userID = %q, want %q (local user, not remote echo)", resp.UserID, expectedUserID)
	}
	if resp.Email != "alice@example.org" {
		t.Errorf("email = %q, want %q (local user email)", resp.Email, "alice@example.org")
	}
	if resp.Name != "Alice A" {
		t.Errorf("name = %q, want %q (local user display name)", resp.Name, "Alice A")
	}

	// Verify invite status was updated
	updated, _ := repo.GetByToken(context.Background(), "valid-token")
	if updated.Status != invites.InviteStatusAccepted {
		t.Errorf("expected status %s, got %s", invites.InviteStatusAccepted, updated.Status)
	}
}

func TestHandleInviteAccepted_Success_EmptyEmailAndName(t *testing.T) {
	repo := invites.NewMemoryOutgoingInviteRepo()
	partyRepo := identity.NewMemoryPartyRepo()

	// Local user with no email or display name
	localUser := &identity.User{
		ID:       "user-uuid-456",
		Username: "bob",
	}
	if err := partyRepo.Create(context.Background(), localUser); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	handler := newTestHandler(repo, partyRepo)

	invite := &invites.OutgoingInvite{
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

	var resp invites.InviteAcceptedResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// Empty email and name are allowed (spec requires the fields but not non-empty values)
	if resp.Email != "" {
		t.Errorf("email = %q, want empty string", resp.Email)
	}
	if resp.Name != "" {
		t.Errorf("name = %q, want empty string", resp.Name)
	}

	// Verify invite status was updated
	updated, _ := repo.GetByToken(context.Background(), "valid-token")
	if updated.Status != invites.InviteStatusAccepted {
		t.Errorf("expected status %s, got %s", invites.InviteStatusAccepted, updated.Status)
	}
}

func TestHandleInviteAccepted_LegacyInvite_PlaceholderIdentity(t *testing.T) {
	repo := invites.NewMemoryOutgoingInviteRepo()
	partyRepo := identity.NewMemoryPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	// Legacy invite: CreatedByUserID is empty (created before this change)
	invite := &invites.OutgoingInvite{
		Token:           "legacy-token",
		ProviderFQDN:    testProvider,
		CreatedByUserID: "", // legacy
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	repo.Create(context.Background(), invite)

	w := postInviteAccepted(handler, `{"token":"legacy-token","recipientProvider":"other.com","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for legacy backfill, got %d: %s", w.Code, w.Body.String())
	}

	var resp invites.InviteAcceptedResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// Backfill: placeholder identity (F5=A)
	expectedUserID := address.FormatOutgoing("unknown", testProvider)
	if resp.UserID != expectedUserID {
		t.Errorf("userID = %q, want %q (placeholder for legacy)", resp.UserID, expectedUserID)
	}
	if resp.Email != "" {
		t.Errorf("email = %q, want empty (legacy backfill)", resp.Email)
	}
	if resp.Name != "" {
		t.Errorf("name = %q, want empty (legacy backfill)", resp.Name)
	}
}

// --- HandleInviteAccepted content type and method tests ---

func TestHandleInviteAccepted_StrictContentType(t *testing.T) {
	repo := invites.NewMemoryOutgoingInviteRepo()
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

// --- HandleCreateOutgoing tests ---

func TestHandleCreateOutgoing_Success(t *testing.T) {
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := invites.NewHandler(repo, nil, "example.com:9200", "https://example.com:9200", nil, testLogger)

	req := httptest.NewRequest(http.MethodPost, "/api/invites/outgoing", nil)
	w := httptest.NewRecorder()

	handler.HandleCreateOutgoing(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp invites.CreateOutgoingResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.InviteString == "" {
		t.Error("inviteString is empty")
	}
	if resp.Token == "" {
		t.Error("token is empty")
	}
	if resp.ProviderFQDN != "example.com:9200" {
		t.Errorf("providerFqdn = %q, want %q", resp.ProviderFQDN, "example.com:9200")
	}

	// Verify token is stored
	stored, err := repo.GetByToken(context.Background(), resp.Token)
	if err != nil {
		t.Errorf("failed to get stored invite: %v", err)
	}
	if stored.InviteString != resp.InviteString {
		t.Errorf("stored inviteString mismatch")
	}
}

func TestHandleCreateOutgoing_SetsCreatedByUserID(t *testing.T) {
	repo := invites.NewMemoryOutgoingInviteRepo()
	user := &identity.User{
		ID:       "creator-uuid",
		Username: "alice",
	}
	handler := newTestHandlerWithCurrentUser(repo, user)

	req := httptest.NewRequest(http.MethodPost, "/api/invites/outgoing", nil)
	w := httptest.NewRecorder()

	handler.HandleCreateOutgoing(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp invites.CreateOutgoingResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// Verify CreatedByUserID is stored
	stored, err := repo.GetByToken(context.Background(), resp.Token)
	if err != nil {
		t.Fatalf("failed to get stored invite: %v", err)
	}
	if stored.CreatedByUserID != "creator-uuid" {
		t.Errorf("CreatedByUserID = %q, want %q", stored.CreatedByUserID, "creator-uuid")
	}
}

func TestHandleCreateOutgoing_NilCurrentUser_NoCreatedByUserID(t *testing.T) {
	repo := invites.NewMemoryOutgoingInviteRepo()
	// handler without currentUser (like the OCM service instance)
	handler := invites.NewHandler(repo, nil, testProvider, testPublicOrigin, nil, testLogger)

	req := httptest.NewRequest(http.MethodPost, "/api/invites/outgoing", nil)
	w := httptest.NewRecorder()

	handler.HandleCreateOutgoing(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp invites.CreateOutgoingResponse
	json.NewDecoder(w.Body).Decode(&resp)

	stored, _ := repo.GetByToken(context.Background(), resp.Token)
	if stored.CreatedByUserID != "" {
		t.Errorf("CreatedByUserID = %q, want empty (no currentUser)", stored.CreatedByUserID)
	}
}

// --- Response field presence test ---

func TestHandleInviteAccepted_ResponseFieldsAlwaysPresent(t *testing.T) {
	repo := invites.NewMemoryOutgoingInviteRepo()
	partyRepo := identity.NewMemoryPartyRepo()

	localUser := &identity.User{
		ID:       "user-uuid-789",
		Username: "charlie",
		// Email and DisplayName intentionally empty
	}
	partyRepo.Create(context.Background(), localUser)

	handler := newTestHandler(repo, partyRepo)

	invite := &invites.OutgoingInvite{
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
			t.Errorf("field %q is missing from response (spec requires it even when empty)", field)
		}
	}
}
