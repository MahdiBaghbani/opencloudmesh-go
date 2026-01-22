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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
)

func TestHandler_CreateOutgoing(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := invites.NewHandler(repo, "example.com:9200", logger)

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

func TestHandler_InviteAccepted_MissingFields(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := invites.NewHandler(repo, "example.com", logger)

	tests := []struct {
		name string
		body string
	}{
		{"missing token", `{"recipientProvider":"other.com"}`},
		{"missing recipientProvider", `{"token":"abc123"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.HandleInviteAccepted(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", w.Code)
			}
		})
	}
}

func TestHandler_InviteAccepted_TokenNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := invites.NewHandler(repo, "example.com", logger)

	body := `{"token":"nonexistent","recipientProvider":"other.com"}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleInviteAccepted(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandler_InviteAccepted_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := invites.NewHandler(repo, "example.com", logger)

	// Create an invite first
	invite := &invites.OutgoingInvite{
		Token:        "valid-token",
		ProviderFQDN: "example.com",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Status:       invites.InviteStatusPending,
	}
	repo.Create(context.Background(), invite)

	body := `{"token":"valid-token","recipientProvider":"other.com","userID":"user123"}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleInviteAccepted(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify invite status updated
	updated, _ := repo.GetByToken(context.Background(), "valid-token")
	if updated.Status != invites.InviteStatusAccepted {
		t.Errorf("expected status %s, got %s", invites.InviteStatusAccepted, updated.Status)
	}
	if updated.AcceptedBy != "other.com" {
		t.Errorf("expected acceptedBy %q, got %q", "other.com", updated.AcceptedBy)
	}
}

func TestHandler_InviteAccepted_RecipientProviderWithScheme(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := invites.NewHandler(repo, "example.com", logger)

	body := `{"token":"abc","recipientProvider":"https://other.com"}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleInviteAccepted(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_format" {
		t.Errorf("expected error 'invalid_format', got %q", resp["error"])
	}
}

func TestHandler_InviteAccepted_StrictContentType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := invites.NewHandler(repo, "example.com", logger)

	req := httptest.NewRequest(http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString("token=abc&recipientProvider=other.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.HandleInviteAccepted(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", w.Code)
	}
}

func TestHandler_InviteAccepted_Idempotent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := invites.NewMemoryOutgoingInviteRepo()
	handler := invites.NewHandler(repo, "example.com", logger)

	// Create an already accepted invite
	invite := &invites.OutgoingInvite{
		Token:        "accepted-token",
		ProviderFQDN: "example.com",
		Status:       invites.InviteStatusAccepted,
	}
	repo.Create(context.Background(), invite)

	body := `{"token":"accepted-token","recipientProvider":"other.com"}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleInviteAccepted(w, req)

	// Idempotent success
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for idempotent accept, got %d", w.Code)
	}
}
