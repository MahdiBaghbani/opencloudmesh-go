package invites_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	inboxinvites "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

const (
	userAID = "user-a-uuid"
	userBID = "user-b-uuid"
)

// currentUserFunc returns a CurrentUser resolver that always returns the given user.
func currentUserFunc(user *identity.User) func(context.Context) (*identity.User, error) {
	return func(ctx context.Context) (*identity.User, error) {
		if user == nil {
			return nil, fmt.Errorf("no authenticated user in context")
		}
		return user, nil
	}
}

// newTestRouter mounts the inbox invites handler on a Chi router.
// httpClient, discoveryClient, signer, and outboundPolicy are nil for unit tests
// (they are only needed for the accept flow which sends outbound requests).
func newTestRouter(repo invitesinbox.IncomingInviteRepo, user *identity.User) http.Handler {
	h := inboxinvites.NewHandler(
		repo,
		nil, // httpClient
		nil, // discoveryClient
		nil, // signer
		nil, // outboundPolicy
		"localhost:9200",
		currentUserFunc(user),
		testLogger,
	)
	r := chi.NewRouter()
	r.Route("/inbox/invites", func(r chi.Router) {
		r.Get("/", h.HandleList)
		r.Post("/import", h.HandleImport)
		r.Post("/{inviteId}/accept", h.HandleAccept)
		r.Post("/{inviteId}/decline", h.HandleDecline)
	})
	return r
}

// createInviteForUser creates an incoming invite owned by the given user.
func createInviteForUser(repo *invitesinbox.MemoryIncomingInviteRepo, recipientUserID, token, senderFQDN string) *invitesinbox.IncomingInvite {
	invite := &invitesinbox.IncomingInvite{
		Token:           token,
		SenderFQDN:      senderFQDN,
		RecipientUserID: recipientUserID,
		Status:          invites.InviteStatusPending,
	}
	repo.Create(context.Background(), invite)
	return invite
}

// buildInviteString creates a base64 invite string from token and provider FQDN.
func buildInviteString(token, providerFQDN string) string {
	inner := token + "@" + providerFQDN
	return base64.StdEncoding.EncodeToString([]byte(inner))
}

func TestHandleList_ReturnsOnlyCurrentUserInvites(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	invA := createInviteForUser(repo, userAID, "token-a", "sender-a.example.com")
	createInviteForUser(repo, userBID, "token-b", "sender-b.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/invites/", nil)
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
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	createInviteForUser(repo, userAID, "token-a", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(repo, userB)

	req := httptest.NewRequest(http.MethodGet, "/inbox/invites/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp inboxinvites.InboxListResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if len(resp.Invites) != 0 {
		t.Errorf("expected empty list for user B, got %d invites", len(resp.Invites))
	}
}

func TestHandleList_Unauthenticated(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	router := newTestRouter(repo, nil)

	req := httptest.NewRequest(http.MethodGet, "/inbox/invites/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleList_DoesNotLeakToken(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	createInviteForUser(repo, userAID, "super-secret-token-123", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/invites/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, "super-secret-token-123") {
		t.Error("response contains invite token -- must not be leaked")
	}
}

func TestHandleImport_Success(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	inviteStr := buildInviteString("import-token-1", "remote.example.com")
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

	// Token must not appear in response
	respBody := w.Body.String()
	if strings.Contains(respBody, "import-token-1") {
		t.Error("response contains token -- must not be leaked")
	}
}

func TestHandleImport_Idempotent(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	inviteStr := buildInviteString("idem-token", "remote.example.com")
	body := fmt.Sprintf(`{"inviteString":"%s"}`, inviteStr)

	// First import
	req1 := httptest.NewRequest(http.MethodPost, "/inbox/invites/import", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	if w1.Code != http.StatusCreated {
		t.Fatalf("first import: expected 201, got %d", w1.Code)
	}

	var resp1 inboxinvites.InviteImportResponse
	json.Unmarshal(w1.Body.Bytes(), &resp1)

	// Second import (same token, same user) - idempotent
	req2 := httptest.NewRequest(http.MethodPost, "/inbox/invites/import", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("idempotent import: expected 200, got %d", w2.Code)
	}

	var resp2 inboxinvites.InviteImportResponse
	json.Unmarshal(w2.Body.Bytes(), &resp2)

	if resp1.ID != resp2.ID {
		t.Errorf("idempotent import should return same ID: got %s vs %s", resp1.ID, resp2.ID)
	}
}

func TestHandleImport_InvalidInviteString(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

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
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

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
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	router := newTestRouter(repo, nil)

	inviteStr := buildInviteString("token", "remote.example.com")
	body := fmt.Sprintf(`{"inviteString":"%s"}`, inviteStr)
	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleAccept_CrossUserReturns404(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	invite := createInviteForUser(repo, userAID, "accept-token", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(repo, userB)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user accept, got %d", w.Code)
	}
}

func TestHandleAccept_NonexistentReturns404(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/nonexistent-id/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleAccept_IdempotentForAlreadyAccepted(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	invite := createInviteForUser(repo, userAID, "idem-accept-token", "sender.example.com")

	// Pre-accept
	repo.UpdateStatusForRecipientUserID(context.Background(), invite.ID, userAID, invites.InviteStatusAccepted)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for idempotent accept, got %d", w.Code)
	}
}

func TestHandleAccept_ConflictForDeclinedInvite(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	invite := createInviteForUser(repo, userAID, "conflict-token", "sender.example.com")

	// The decline handler deletes the invite, so to test this we need to
	// manually set status to declined without deleting
	repo.UpdateStatusForRecipientUserID(context.Background(), invite.ID, userAID, invites.InviteStatusDeclined)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for accepting a declined invite, got %d", w.Code)
	}
}

func TestHandleAccept_Unauthenticated(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	router := newTestRouter(repo, nil)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/some-id/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleDecline_Success(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	invite := createInviteForUser(repo, userAID, "decline-token", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/"+invite.ID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify invite was deleted (not just status changed)
	_, err := repo.GetByIDForRecipientUserID(context.Background(), invite.ID, userAID)
	if err == nil {
		t.Error("expected invite to be deleted after decline")
	}
}

func TestHandleDecline_CrossUserReturns404(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	invite := createInviteForUser(repo, userAID, "decline-cross-token", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(repo, userB)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/"+invite.ID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user decline, got %d", w.Code)
	}
}

func TestHandleDecline_Unauthenticated(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	router := newTestRouter(repo, nil)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/some-id/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleImport_DifferentUsersCanImportSameToken(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	inviteStr := buildInviteString("shared-token", "remote.example.com")
	body := fmt.Sprintf(`{"inviteString":"%s"}`, inviteStr)

	// User A imports
	userA := &identity.User{ID: userAID, Username: "alice"}
	routerA := newTestRouter(repo, userA)
	req1 := httptest.NewRequest(http.MethodPost, "/inbox/invites/import", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	routerA.ServeHTTP(w1, req1)

	if w1.Code != http.StatusCreated {
		t.Fatalf("user A import: expected 201, got %d", w1.Code)
	}

	// User B imports the same token (different user, should succeed as a new invite)
	userB := &identity.User{ID: userBID, Username: "bob"}
	routerB := newTestRouter(repo, userB)
	req2 := httptest.NewRequest(http.MethodPost, "/inbox/invites/import", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	routerB.ServeHTTP(w2, req2)

	if w2.Code != http.StatusCreated {
		t.Fatalf("user B import: expected 201, got %d: %s", w2.Code, w2.Body.String())
	}

	// Each user should see only their own invite
	invitesA, _ := repo.ListByRecipientUserID(context.Background(), userAID)
	invitesB, _ := repo.ListByRecipientUserID(context.Background(), userBID)

	if len(invitesA) != 1 {
		t.Errorf("expected 1 invite for user A, got %d", len(invitesA))
	}
	if len(invitesB) != 1 {
		t.Errorf("expected 1 invite for user B, got %d", len(invitesB))
	}
}
