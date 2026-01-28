package shares_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
)

// MockNotificationSender is a mock for testing.
type MockNotificationSender struct {
	AcceptCalls  []string
	DeclineCalls []string
	ShouldFail   bool
}

func (m *MockNotificationSender) SendShareAccepted(ctx context.Context, targetHost, providerID, resourceType string) error {
	m.AcceptCalls = append(m.AcceptCalls, providerID)
	return nil
}

func (m *MockNotificationSender) SendShareDeclined(ctx context.Context, targetHost, providerID, resourceType string) error {
	m.DeclineCalls = append(m.DeclineCalls, providerID)
	return nil
}

// createTestShare creates a share with empty RecipientUserID (matches the
// temporary "" the actions handler passes until p07 injects CurrentUser).
func createTestShare(repo *shares.MemoryIncomingShareRepo, providerID, senderHost string, status shares.ShareStatus) *shares.IncomingShare {
	share := &shares.IncomingShare{
		ProviderID:      providerID,
		SenderHost:      senderHost,
		ShareWith:       "user@example.com",
		RecipientUserID: "", // temporary: matches handler's "" until p07
		Status:          status,
		ResourceType:    "file",
	}
	repo.Create(context.Background(), share)
	return share
}

func TestInboxActionsHandler_AcceptShare(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryIncomingShareRepo()
	sender := &MockNotificationSender{}
	handler := shares.NewInboxActionsHandler(repo, sender, logger)

	share := createTestShare(repo, "provider-123", "sender.example.com", shares.ShareStatusPending)

	req := httptest.NewRequest(http.MethodPost, "/api/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()

	handler.HandleAccept(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if len(sender.AcceptCalls) != 1 {
		t.Errorf("expected 1 accept call, got %d", len(sender.AcceptCalls))
	}

	updated, _ := repo.GetByIDForRecipientUserID(context.Background(), share.ShareID, "")
	if updated.Status != shares.ShareStatusAccepted {
		t.Errorf("expected status %s, got %s", shares.ShareStatusAccepted, updated.Status)
	}
}

func TestInboxActionsHandler_DeclineShare(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryIncomingShareRepo()
	sender := &MockNotificationSender{}
	handler := shares.NewInboxActionsHandler(repo, sender, logger)

	share := createTestShare(repo, "provider-456", "sender.example.com", shares.ShareStatusPending)

	req := httptest.NewRequest(http.MethodPost, "/api/inbox/shares/"+share.ShareID+"/decline", nil)
	w := httptest.NewRecorder()

	handler.HandleDecline(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if len(sender.DeclineCalls) != 1 {
		t.Errorf("expected 1 decline call, got %d", len(sender.DeclineCalls))
	}

	updated, _ := repo.GetByIDForRecipientUserID(context.Background(), share.ShareID, "")
	if updated.Status != shares.ShareStatusDeclined {
		t.Errorf("expected status %s, got %s", shares.ShareStatusDeclined, updated.Status)
	}
}

func TestInboxActionsHandler_IdempotentAccept(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryIncomingShareRepo()
	sender := &MockNotificationSender{}
	handler := shares.NewInboxActionsHandler(repo, sender, logger)

	share := createTestShare(repo, "provider-789", "sender.example.com", shares.ShareStatusAccepted)

	req := httptest.NewRequest(http.MethodPost, "/api/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()

	handler.HandleAccept(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for idempotent accept, got %d", w.Code)
	}

	if len(sender.AcceptCalls) != 0 {
		t.Errorf("expected no accept calls for already accepted share, got %d", len(sender.AcceptCalls))
	}
}

func TestInboxActionsHandler_CannotAcceptDeclined(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryIncomingShareRepo()
	sender := &MockNotificationSender{}
	handler := shares.NewInboxActionsHandler(repo, sender, logger)

	share := createTestShare(repo, "provider-declined", "sender.example.com", shares.ShareStatusDeclined)

	req := httptest.NewRequest(http.MethodPost, "/api/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()

	handler.HandleAccept(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for trying to accept declined share, got %d", w.Code)
	}
}

func TestInboxActionsHandler_ShareNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryIncomingShareRepo()
	sender := &MockNotificationSender{}
	handler := shares.NewInboxActionsHandler(repo, sender, logger)

	req := httptest.NewRequest(http.MethodPost, "/api/inbox/shares/nonexistent/accept", nil)
	w := httptest.NewRecorder()

	handler.HandleAccept(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}
