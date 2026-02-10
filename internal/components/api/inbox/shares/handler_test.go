package shares_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
)

// mockNotificationSender records accept/decline calls for assertions.
type mockNotificationSender struct {
	acceptCalls  []string
	declineCalls []string
}

func (m *mockNotificationSender) SendShareAccepted(ctx context.Context, targetHost, providerID, resourceType string) error {
	m.acceptCalls = append(m.acceptCalls, providerID)
	return nil
}

func (m *mockNotificationSender) SendShareDeclined(ctx context.Context, targetHost, providerID, resourceType string) error {
	m.declineCalls = append(m.declineCalls, providerID)
	return nil
}

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

// newTestRouter mounts the inbox shares handler on a Chi router.
func newTestRouter(repo sharesinbox.IncomingShareRepo, sender sharesinbox.NotificationSender, user *identity.User) http.Handler {
	h := inboxshares.NewHandler(repo, sender, currentUserFunc(user), testLogger)
	r := chi.NewRouter()
	r.Route("/inbox/shares", func(r chi.Router) {
		r.Get("/", h.HandleList)
		r.Get("/{shareId}", h.HandleGetDetail)
		r.Post("/{shareId}/accept", h.HandleAccept)
		r.Post("/{shareId}/decline", h.HandleDecline)
	})
	return r
}

// createShareForUser creates a share owned by the given user ID.
func createShareForUser(repo *sharesinbox.MemoryIncomingShareRepo, recipientUserID, providerID, senderHost string) *sharesinbox.IncomingShare {
	share := &sharesinbox.IncomingShare{
		ProviderID:      providerID,
		SenderHost:      senderHost,
		ShareWith:       recipientUserID + "@example.com",
		RecipientUserID: recipientUserID,
		Status:          sharesinbox.ShareStatusPending,
		ResourceType:    "file",
		Name:            "test-share-" + providerID,
		Owner:           "owner@sender.example.com",
		Sender:          "sender@sender.example.com",
		ShareType:       "user",
	}
	repo.Create(context.Background(), share)
	return share
}

func TestHandleList_ReturnsOnlyCurrentUserShares(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	shareA := createShareForUser(repo, userAID, "prov-a1", "sender.example.com")
	createShareForUser(repo, userBID, "prov-b1", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, nil, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/", nil)
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
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	createShareForUser(repo, userAID, "prov-a1", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(repo, nil, userB)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp inboxshares.InboxListResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if len(resp.Shares) != 0 {
		t.Errorf("expected empty list for user B, got %d shares", len(resp.Shares))
	}
}

func TestHandleList_Unauthenticated(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	router := newTestRouter(repo, nil, nil) // nil user = unauthenticated

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleAccept_Success(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	sender := &mockNotificationSender{}
	share := createShareForUser(repo, userAID, "prov-accept", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, sender, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify share was updated
	updated, _ := repo.GetByIDForRecipientUserID(context.Background(), share.ShareID, userAID)
	if updated.Status != sharesinbox.ShareStatusAccepted {
		t.Errorf("expected status %s, got %s", sharesinbox.ShareStatusAccepted, updated.Status)
	}

	// Verify notification was sent
	if len(sender.acceptCalls) != 1 {
		t.Errorf("expected 1 accept notification, got %d", len(sender.acceptCalls))
	}
}

func TestHandleAccept_CrossUserReturns404(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-cross", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(repo, nil, userB)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user accept, got %d", w.Code)
	}
}

func TestHandleAccept_NonexistentShareReturns404(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, nil, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/nonexistent-id/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleAccept_IdempotentForAlreadyAccepted(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	sender := &mockNotificationSender{}
	share := createShareForUser(repo, userAID, "prov-idem", "sender.example.com")

	// Pre-accept the share
	repo.UpdateStatusForRecipientUserID(context.Background(), share.ShareID, userAID, sharesinbox.ShareStatusAccepted)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, sender, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for idempotent accept, got %d", w.Code)
	}

	// No notification should be sent for already-accepted
	if len(sender.acceptCalls) != 0 {
		t.Errorf("expected no accept notifications, got %d", len(sender.acceptCalls))
	}
}

func TestHandleAccept_ConflictForDeclinedShare(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-declined", "sender.example.com")

	repo.UpdateStatusForRecipientUserID(context.Background(), share.ShareID, userAID, sharesinbox.ShareStatusDeclined)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, nil, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for accepting a declined share, got %d", w.Code)
	}
}

func TestHandleAccept_Unauthenticated(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	router := newTestRouter(repo, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/some-id/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleDecline_Success(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	sender := &mockNotificationSender{}
	share := createShareForUser(repo, userAID, "prov-decline", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, sender, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated, _ := repo.GetByIDForRecipientUserID(context.Background(), share.ShareID, userAID)
	if updated.Status != sharesinbox.ShareStatusDeclined {
		t.Errorf("expected status %s, got %s", sharesinbox.ShareStatusDeclined, updated.Status)
	}

	if len(sender.declineCalls) != 1 {
		t.Errorf("expected 1 decline notification, got %d", len(sender.declineCalls))
	}
}

func TestHandleDecline_CrossUserReturns404(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-cross-dec", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(repo, nil, userB)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user decline, got %d", w.Code)
	}
}

func TestHandleDecline_ConflictForAcceptedShare(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-acc-dec", "sender.example.com")

	repo.UpdateStatusForRecipientUserID(context.Background(), share.ShareID, userAID, sharesinbox.ShareStatusAccepted)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, nil, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/decline", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for declining an accepted share, got %d", w.Code)
	}
}

func TestHandleList_DoesNotLeakSensitiveFields(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := &sharesinbox.IncomingShare{
		ProviderID:           "prov-sensitive",
		SenderHost:           "sender.example.com",
		ShareWith:            userAID + "@example.com",
		RecipientUserID:      userAID,
		RecipientDisplayName: "Alice A",
		SharedSecret:         "super-secret-token",
		Status:               sharesinbox.ShareStatusPending,
		ResourceType:         "file",
		Name:                 "test-share",
		Owner:                "owner@sender.example.com",
		Sender:               "sender@sender.example.com",
		ShareType:            "user",
	}
	repo.Create(context.Background(), share)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, nil, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	body := w.Body.String()

	// SharedSecret must not appear
	if containsStr(body, "super-secret-token") {
		t.Error("response contains SharedSecret -- must not be leaked")
	}

	// RecipientUserID and RecipientDisplayName are json:"-" so must not appear
	if containsStr(body, "recipientUserID") || containsStr(body, "RecipientUserID") {
		t.Error("response contains RecipientUserID field name -- must not be leaked")
	}
}

// createDetailedShareForUser creates a share with WebDAV detail fields set.
func createDetailedShareForUser(
	repo *sharesinbox.MemoryIncomingShareRepo,
	recipientUserID, providerID, senderHost string,
	webdavID, webdavURIAbsolute, sharedSecret string,
	mustExchangeToken bool,
) *sharesinbox.IncomingShare {
	share := &sharesinbox.IncomingShare{
		ProviderID:        providerID,
		SenderHost:        senderHost,
		ShareWith:         recipientUserID + "@example.com",
		RecipientUserID:   recipientUserID,
		Status:            sharesinbox.ShareStatusPending,
		ResourceType:      "file",
		Name:              "test-share-" + providerID,
		Owner:             "owner@sender.example.com",
		Sender:            "sender@sender.example.com",
		ShareType:         "user",
		Permissions:       []string{"read"},
		WebDAVID:          webdavID,
		WebDAVURIAbsolute: webdavURIAbsolute,
		SharedSecret:      sharedSecret,
		MustExchangeToken: mustExchangeToken,
	}
	repo.Create(context.Background(), share)
	return share
}

func TestHandleGetDetail_OwnShareReturns200(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createDetailedShareForUser(repo, userAID, "prov-detail", "sender.example.com",
		"webdav-id-123", "", "secret-value", true)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, nil, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+share.ShareID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Base InboxShareView fields
	if resp["shareId"] != share.ShareID {
		t.Errorf("expected shareId %s, got %v", share.ShareID, resp["shareId"])
	}
	if resp["providerId"] != "prov-detail" {
		t.Errorf("expected providerId prov-detail, got %v", resp["providerId"])
	}
	if resp["name"] != share.Name {
		t.Errorf("expected name %s, got %v", share.Name, resp["name"])
	}
	if resp["senderHost"] != "sender.example.com" {
		t.Errorf("expected senderHost sender.example.com, got %v", resp["senderHost"])
	}

	// Detail-specific fields
	if resp["webdavId"] != "webdav-id-123" {
		t.Errorf("expected webdavId webdav-id-123, got %v", resp["webdavId"])
	}
	if resp["mustExchangeToken"] != true {
		t.Errorf("expected mustExchangeToken true, got %v", resp["mustExchangeToken"])
	}
	if resp["webdavUriAbsolutePresent"] != false {
		t.Errorf("expected webdavUriAbsolutePresent false (no absolute URI), got %v", resp["webdavUriAbsolutePresent"])
	}

	// Protocol block
	proto, ok := resp["protocol"].(map[string]any)
	if !ok {
		t.Fatalf("expected protocol to be an object, got %T", resp["protocol"])
	}
	if proto["name"] != "webdav" {
		t.Errorf("expected protocol.name webdav, got %v", proto["name"])
	}
	webdav, ok := proto["webdav"].(map[string]any)
	if !ok {
		t.Fatalf("expected protocol.webdav to be an object, got %T", proto["webdav"])
	}
	if webdav["uri"] != "webdav-id-123" {
		t.Errorf("expected protocol.webdav.uri webdav-id-123, got %v", webdav["uri"])
	}
}

func TestHandleGetDetail_CrossUserReturns404(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createDetailedShareForUser(repo, userAID, "prov-cross-detail", "sender.example.com",
		"wdid", "", "secret", false)

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(repo, nil, userB)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+share.ShareID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user detail, got %d", w.Code)
	}
}

func TestHandleGetDetail_NonexistentReturns404(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, nil, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/nonexistent-id", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleGetDetail_SharedSecretAlwaysRedacted(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createDetailedShareForUser(repo, userAID, "prov-redact", "sender.example.com",
		"wdid", "", "real-secret-value", false)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, nil, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+share.ShareID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()

	// Secret must not appear anywhere
	if containsStr(body, "real-secret-value") {
		t.Error("response contains the actual SharedSecret -- must not be leaked")
	}

	// Redacted value must be present
	if !containsStr(body, "[REDACTED]") {
		t.Error("response does not contain [REDACTED] for sharedSecret")
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	proto := resp["protocol"].(map[string]any)
	webdav := proto["webdav"].(map[string]any)
	if webdav["sharedSecret"] != "[REDACTED]" {
		t.Errorf("expected sharedSecret [REDACTED], got %v", webdav["sharedSecret"])
	}
}

func TestHandleGetDetail_RecipientUserIDNotInResponse(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createDetailedShareForUser(repo, userAID, "prov-noleak", "sender.example.com",
		"wdid", "", "secret", false)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, nil, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+share.ShareID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	body := w.Body.String()

	// RecipientUserID (json:"-") must not appear as a field name in the response.
	// The raw user ID value may appear in shareWith (which is expected), so we only
	// check the field name, not the value.
	if containsStr(body, "recipientUserID") || containsStr(body, "RecipientUserID") {
		t.Error("response contains RecipientUserID field name -- must not be leaked")
	}
	if containsStr(body, "recipientDisplayName") || containsStr(body, "RecipientDisplayName") {
		t.Error("response contains RecipientDisplayName field name -- must not be leaked")
	}
}

func TestHandleGetDetail_RequirementsReflectsMustExchangeToken(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}

	// Case A: MustExchangeToken = true
	shareA := createDetailedShareForUser(repo, userAID, "prov-met-true", "sender.example.com",
		"wdid", "", "secret", true)

	router := newTestRouter(repo, nil, userA)

	reqA := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+shareA.ShareID, nil)
	wA := httptest.NewRecorder()
	router.ServeHTTP(wA, reqA)

	var respA map[string]any
	json.Unmarshal(wA.Body.Bytes(), &respA)
	protoA := respA["protocol"].(map[string]any)
	webdavA := protoA["webdav"].(map[string]any)
	reqsA, ok := webdavA["requirements"].([]any)
	if !ok {
		t.Fatalf("expected requirements to be an array, got %T", webdavA["requirements"])
	}
	if len(reqsA) != 1 || reqsA[0] != "must-exchange-token" {
		t.Errorf("expected requirements [must-exchange-token], got %v", reqsA)
	}

	// Case B: MustExchangeToken = false
	shareB := createDetailedShareForUser(repo, userAID, "prov-met-false", "sender.example.com",
		"wdid2", "", "secret2", false)

	reqB := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+shareB.ShareID, nil)
	wB := httptest.NewRecorder()
	router.ServeHTTP(wB, reqB)

	var respB map[string]any
	json.Unmarshal(wB.Body.Bytes(), &respB)
	protoB := respB["protocol"].(map[string]any)
	webdavB := protoB["webdav"].(map[string]any)
	reqsB, ok := webdavB["requirements"].([]any)
	if !ok {
		t.Fatalf("expected requirements to be an array, got %T", webdavB["requirements"])
	}
	if len(reqsB) != 0 {
		t.Errorf("expected empty requirements for MustExchangeToken=false, got %v", reqsB)
	}
}

func TestHandleGetDetail_Unauthenticated(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	router := newTestRouter(repo, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/some-id", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleGetDetail_NilPermissionsSerializesAsEmptyArray(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	// Create share without setting Permissions (nil)
	share := &sharesinbox.IncomingShare{
		ProviderID:      "prov-nilperms",
		SenderHost:      "sender.example.com",
		ShareWith:       userAID + "@example.com",
		RecipientUserID: userAID,
		Status:          sharesinbox.ShareStatusPending,
		ResourceType:    "file",
		Name:            "test-share-nilperms",
		Owner:           "owner@sender.example.com",
		Sender:          "sender@sender.example.com",
		ShareType:       "user",
		WebDAVID:        "wdid",
		SharedSecret:    "secret",
	}
	repo.Create(context.Background(), share)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, nil, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+share.ShareID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	proto := resp["protocol"].(map[string]any)
	webdav := proto["webdav"].(map[string]any)

	// Permissions must be [] not null when the share has nil permissions
	perms, ok := webdav["permissions"].([]any)
	if !ok {
		t.Fatalf("expected permissions to be an array, got %T (likely null)", webdav["permissions"])
	}
	if len(perms) != 0 {
		t.Errorf("expected empty permissions array, got %v", perms)
	}
}

func TestHandleGetDetail_WebDAVURIAbsolutePresent(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, nil, userA)

	// Case A: absolute URI present
	shareA := createDetailedShareForUser(repo, userAID, "prov-abs-yes", "sender.example.com",
		"relative-id", "https://sender.example.com/webdav/file.txt", "secret", false)

	reqA := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+shareA.ShareID, nil)
	wA := httptest.NewRecorder()
	router.ServeHTTP(wA, reqA)

	var respA map[string]any
	json.Unmarshal(wA.Body.Bytes(), &respA)

	if respA["webdavUriAbsolutePresent"] != true {
		t.Errorf("expected webdavUriAbsolutePresent true, got %v", respA["webdavUriAbsolutePresent"])
	}
	protoA := respA["protocol"].(map[string]any)
	webdavA := protoA["webdav"].(map[string]any)
	if webdavA["uri"] != "https://sender.example.com/webdav/file.txt" {
		t.Errorf("expected absolute URI in protocol.webdav.uri, got %v", webdavA["uri"])
	}

	// Case B: no absolute URI
	shareB := createDetailedShareForUser(repo, userAID, "prov-abs-no", "sender.example.com",
		"relative-id-only", "", "secret2", false)

	reqB := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+shareB.ShareID, nil)
	wB := httptest.NewRecorder()
	router.ServeHTTP(wB, reqB)

	var respB map[string]any
	json.Unmarshal(wB.Body.Bytes(), &respB)

	if respB["webdavUriAbsolutePresent"] != false {
		t.Errorf("expected webdavUriAbsolutePresent false, got %v", respB["webdavUriAbsolutePresent"])
	}
	protoB := respB["protocol"].(map[string]any)
	webdavB := protoB["webdav"].(map[string]any)
	if webdavB["uri"] != "relative-id-only" {
		t.Errorf("expected WebDAVID as uri, got %v", webdavB["uri"])
	}
}

func containsStr(haystack, needle string) bool {
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
