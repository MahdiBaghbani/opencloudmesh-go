package shares_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/shares"
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

func TestInboxActionsHandler_AcceptShare(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryIncomingShareRepo()
	sender := &MockNotificationSender{}
	handler := shares.NewInboxActionsHandler(repo, sender, logger)

	// Create a pending share
	share := &shares.IncomingShare{
		ProviderID:   "provider-123",
		SenderHost:   "sender.example.com",
		ShareWith:    "user@example.com",
		Status:       shares.ShareStatusPending,
		ResourceType: "file",
	}
	repo.Create(context.Background(), share)

	req := httptest.NewRequest(http.MethodPost, "/api/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()

	handler.HandleAccept(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify notification was sent
	if len(sender.AcceptCalls) != 1 {
		t.Errorf("expected 1 accept call, got %d", len(sender.AcceptCalls))
	}

	// Verify share status updated
	updated, _ := repo.GetByID(context.Background(), share.ShareID)
	if updated.Status != shares.ShareStatusAccepted {
		t.Errorf("expected status %s, got %s", shares.ShareStatusAccepted, updated.Status)
	}
}

func TestInboxActionsHandler_DeclineShare(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryIncomingShareRepo()
	sender := &MockNotificationSender{}
	handler := shares.NewInboxActionsHandler(repo, sender, logger)

	// Create a pending share
	share := &shares.IncomingShare{
		ProviderID:   "provider-456",
		SenderHost:   "sender.example.com",
		ShareWith:    "user@example.com",
		Status:       shares.ShareStatusPending,
		ResourceType: "file",
	}
	repo.Create(context.Background(), share)

	req := httptest.NewRequest(http.MethodPost, "/api/inbox/shares/"+share.ShareID+"/decline", nil)
	w := httptest.NewRecorder()

	handler.HandleDecline(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify notification was sent
	if len(sender.DeclineCalls) != 1 {
		t.Errorf("expected 1 decline call, got %d", len(sender.DeclineCalls))
	}

	// Verify share status updated
	updated, _ := repo.GetByID(context.Background(), share.ShareID)
	if updated.Status != shares.ShareStatusDeclined {
		t.Errorf("expected status %s, got %s", shares.ShareStatusDeclined, updated.Status)
	}
}

func TestInboxActionsHandler_IdempotentAccept(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryIncomingShareRepo()
	sender := &MockNotificationSender{}
	handler := shares.NewInboxActionsHandler(repo, sender, logger)

	// Create an already accepted share
	share := &shares.IncomingShare{
		ProviderID:   "provider-789",
		SenderHost:   "sender.example.com",
		ShareWith:    "user@example.com",
		Status:       shares.ShareStatusAccepted,
		ResourceType: "file",
	}
	repo.Create(context.Background(), share)

	req := httptest.NewRequest(http.MethodPost, "/api/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()

	handler.HandleAccept(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for idempotent accept, got %d", w.Code)
	}

	// Should not send another notification
	if len(sender.AcceptCalls) != 0 {
		t.Errorf("expected no accept calls for already accepted share, got %d", len(sender.AcceptCalls))
	}
}

func TestInboxActionsHandler_CannotAcceptDeclined(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryIncomingShareRepo()
	sender := &MockNotificationSender{}
	handler := shares.NewInboxActionsHandler(repo, sender, logger)

	// Create a declined share
	share := &shares.IncomingShare{
		ProviderID:   "provider-declined",
		SenderHost:   "sender.example.com",
		ShareWith:    "user@example.com",
		Status:       shares.ShareStatusDeclined,
		ResourceType: "file",
	}
	repo.Create(context.Background(), share)

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
