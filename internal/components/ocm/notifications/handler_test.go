package notifications_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
)

func TestHandler_MissingFields(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryOutgoingShareRepo()
	handler := notifications.NewHandler(repo, "https://example.com", logger)

	tests := []struct {
		name string
		body string
	}{
		{"missing notificationType", `{"resourceType":"file","providerId":"abc"}`},
		{"missing resourceType", `{"notificationType":"SHARE_ACCEPTED","providerId":"abc"}`},
		{"missing providerId", `{"notificationType":"SHARE_ACCEPTED","resourceType":"file"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/ocm/notifications", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.HandleNotification(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandler_InvalidNotificationType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryOutgoingShareRepo()
	handler := notifications.NewHandler(repo, "https://example.com", logger)

	body := `{"notificationType":"UNKNOWN_TYPE","resourceType":"file","providerId":"abc"}`

	req := httptest.NewRequest(http.MethodPost, "/ocm/notifications", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleNotification(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_notification_type" {
		t.Errorf("expected error 'invalid_notification_type', got %q", resp["error"])
	}
}

func TestHandler_ShareNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryOutgoingShareRepo()
	handler := notifications.NewHandler(repo, "https://example.com", logger)

	body := `{"notificationType":"SHARE_ACCEPTED","resourceType":"file","providerId":"nonexistent"}`

	req := httptest.NewRequest(http.MethodPost, "/ocm/notifications", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleNotification(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandler_SuccessfulNotification(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryOutgoingShareRepo()

	// Create an outgoing share
	share := &shares.OutgoingShare{
		ProviderID:   "provider-123",
		WebDAVID:     "webdav-456",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
		Status:       "sent",
	}
	repo.Create(context.Background(), share)

	handler := notifications.NewHandler(repo, "https://example.com", logger)

	body := `{"notificationType":"SHARE_ACCEPTED","resourceType":"file","providerId":"provider-123"}`

	req := httptest.NewRequest(http.MethodPost, "/ocm/notifications", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleNotification(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIsValidNotificationType(t *testing.T) {
	tests := []struct {
		notificationType notifications.NotificationType
		valid            bool
	}{
		{notifications.NotificationShareAccepted, true},
		{notifications.NotificationShareDeclined, true},
		{notifications.NotificationShareUnshared, true},
		{"UNKNOWN", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.notificationType), func(t *testing.T) {
			result := notifications.IsValidNotificationType(tt.notificationType)
			if result != tt.valid {
				t.Errorf("IsValidNotificationType(%q) = %v, want %v", tt.notificationType, result, tt.valid)
			}
		})
	}
}
