package incoming_test

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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

func TestHandler_MissingFields(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	handler := incoming.NewHandler(repo, "https://example.com", logger)

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
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	handler := incoming.NewHandler(repo, "https://example.com", logger)

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
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	handler := incoming.NewHandler(repo, "https://example.com", logger)

	body := `{"notificationType":"SHARE_ACCEPTED","resourceType":"file","providerId":"nonexistent"}`

	req := httptest.NewRequest(http.MethodPost, "/ocm/notifications", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleNotification(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["reasonCode"] != reason.PeerCapabilityMismatch {
		t.Errorf("expected reasonCode %q, got %q", reason.PeerCapabilityMismatch, resp["reasonCode"])
	}
}

func TestHandler_SuccessfulNotification(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()

	// Create an outgoing share
	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-123",
		WebDAVID:     "webdav-456",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
		Status:       "sent",
	}
	repo.Create(context.Background(), share)

	handler := incoming.NewHandler(repo, "https://example.com", logger)

	body := `{"notificationType":"SHARE_ACCEPTED","resourceType":"file","providerId":"provider-123"}`

	req := httptest.NewRequest(http.MethodPost, "/ocm/notifications", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleNotification(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_SenderMismatchReasonCode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-mismatch",
		WebDAVID:     "webdav-456",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
		Status:       "sent",
	}
	repo.Create(context.Background(), share)
	handler := incoming.NewHandler(repo, "https://example.com", logger)

	body := `{"notificationType":"SHARE_ACCEPTED","resourceType":"file","providerId":"provider-mismatch"}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/notifications", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), crypto.PeerIdentityKey, &crypto.PeerIdentity{
		Authenticated:       true,
		AuthorityForCompare: "wrong.example.com",
	}))
	w := httptest.NewRecorder()

	handler.HandleNotification(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "sender_mismatch" {
		t.Fatalf("expected sender_mismatch, got %q", resp["error"])
	}
	if resp["reasonCode"] != reason.PeerPolicyUnsatisfied {
		t.Fatalf("expected reasonCode %q, got %q", reason.PeerPolicyUnsatisfied, resp["reasonCode"])
	}
}

// TestHandler_EmptyPublicOrigin_NoHTTPSDefault proves that an empty
// publicOrigin leaves localScheme empty (not forced to "https"). With an empty
// scheme, hostport.Normalize preserves the explicit :443 port, so a share
// receiver of "receiver.example.com:443" does not collapse to the bare
// "receiver.example.com" sender authority and the request is rejected as a
// mismatch. If the scheme were forced to "https", :443 would be stripped and
// the request would incorrectly succeed.
func TestHandler_EmptyPublicOrigin_NoHTTPSDefault(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-empty-origin",
		WebDAVID:     "webdav-empty-origin",
		ReceiverHost: "receiver.example.com:443",
		LocalPath:    "/tmp/test.txt",
		Status:       "sent",
	}
	repo.Create(context.Background(), share)
	handler := incoming.NewHandler(repo, "", logger)

	body := `{"notificationType":"SHARE_ACCEPTED","resourceType":"file","providerId":"provider-empty-origin"}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/notifications", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), crypto.PeerIdentityKey, &crypto.PeerIdentity{
		Authenticated:       true,
		AuthorityForCompare: "receiver.example.com",
	}))
	w := httptest.NewRecorder()

	handler.HandleNotification(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (empty scheme keeps :443, so no match), got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "sender_mismatch" {
		t.Fatalf("expected sender_mismatch, got %q", resp["error"])
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
