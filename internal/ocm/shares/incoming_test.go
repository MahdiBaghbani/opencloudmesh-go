package shares_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/shares"
)

func TestValidateNewShareRequest_RequiredFields(t *testing.T) {
	req := &shares.NewShareRequest{}
	errs := shares.ValidateNewShareRequest(req, true)

	if !errs.HasErrors() {
		t.Error("expected validation errors for empty request")
	}

	// Check that all required fields are flagged
	fields := map[string]bool{}
	for _, e := range errs.Errors {
		fields[e.Field] = true
	}

	required := []string{"shareWith", "name", "providerId", "owner", "sender", "shareType", "resourceType"}
	for _, f := range required {
		if !fields[f] {
			t.Errorf("expected validation error for field %s", f)
		}
	}
}

func TestValidateNewShareRequest_MissingSharedSecret(t *testing.T) {
	req := &shares.NewShareRequest{
		ShareWith:    "user@example.com",
		Name:         "test.txt",
		ProviderID:   "abc123",
		Owner:        "owner@sender.com",
		Sender:       "sender@sender.com",
		ShareType:    "user",
		ResourceType: "file",
		Protocol: shares.Protocol{
			WebDAV: &shares.WebDAVProtocol{
				URI:         "abc123",
				Permissions: []string{"read"},
				// Missing SharedSecret
			},
		},
	}

	// Strict mode should reject missing sharedSecret
	errs := shares.ValidateNewShareRequest(req, true)
	if !errs.HasErrors() {
		t.Error("expected validation error for missing sharedSecret in strict mode")
	}

	found := false
	for _, e := range errs.Errors {
		if e.Field == "protocol.webdav.sharedSecret" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected specific error for sharedSecret")
	}

	// Non-strict mode should accept missing sharedSecret
	errs = shares.ValidateNewShareRequest(req, false)
	hasSecretError := false
	for _, e := range errs.Errors {
		if e.Field == "protocol.webdav.sharedSecret" {
			hasSecretError = true
			break
		}
	}
	if hasSecretError {
		t.Error("should not error on missing sharedSecret in non-strict mode")
	}
}

func TestValidateNewShareRequest_MustExchangeToken(t *testing.T) {
	req := &shares.NewShareRequest{
		ShareWith:    "user@example.com",
		Name:         "test.txt",
		ProviderID:   "abc123",
		Owner:        "owner@sender.com",
		Sender:       "sender@sender.com",
		ShareType:    "user",
		ResourceType: "file",
		Protocol: shares.Protocol{
			WebDAV: &shares.WebDAVProtocol{
				URI:          "abc123",
				SharedSecret: "secret",
				Permissions:  []string{"read"},
				Requirements: []string{"must-exchange-token"},
			},
		},
	}

	errs := shares.ValidateNewShareRequest(req, false)
	if !errs.HasErrors() {
		t.Error("expected validation error for must-exchange-token")
	}

	found := false
	for _, e := range errs.Errors {
		if e.Field == "protocol.webdav.requirements" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected specific error for must-exchange-token requirement")
	}
}

func TestIncomingHandler_CreateShare(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryIncomingShareRepo()
	handler := shares.NewIncomingHandler(repo, nil, logger, false)

	body := `{
		"shareWith": "user@example.com",
		"name": "test.txt",
		"providerId": "abc123",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"webdav": {
				"uri": "abc123",
				"sharedSecret": "secret123",
				"permissions": ["read"]
			}
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIncomingHandler_CreateShare_ValidationError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryIncomingShareRepo()
	handler := shares.NewIncomingHandler(repo, nil, logger, false)

	// Missing required fields
	body := `{"name": "test.txt"}`

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	var resp shares.ValidationErrors
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.Errors) == 0 {
		t.Error("expected validation errors in response")
	}
}

func TestIncomingRepository_SenderScopedStorage(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()

	// Create share from sender1
	share1 := &shares.IncomingShare{
		ProviderID: "same-id",
		SenderHost: "sender1.example.com",
		ShareWith:  "user@example.com",
		Status:     shares.ShareStatusPending,
	}
	if err := repo.Create(ctx, share1); err != nil {
		t.Fatalf("failed to create share1: %v", err)
	}

	// Create share with same providerId from sender2 - should succeed
	share2 := &shares.IncomingShare{
		ProviderID: "same-id",
		SenderHost: "sender2.example.com",
		ShareWith:  "user@example.com",
		Status:     shares.ShareStatusPending,
	}
	if err := repo.Create(ctx, share2); err != nil {
		t.Fatalf("failed to create share2: %v", err)
	}

	// Try to create duplicate from sender1 - should fail
	share3 := &shares.IncomingShare{
		ProviderID: "same-id",
		SenderHost: "sender1.example.com",
		ShareWith:  "user@example.com",
		Status:     shares.ShareStatusPending,
	}
	if err := repo.Create(ctx, share3); err == nil {
		t.Error("expected error for duplicate providerId from same sender")
	}

	// Lookup by sender-scoped providerId
	found, err := repo.GetByProviderID(ctx, "sender1.example.com", "same-id")
	if err != nil {
		t.Fatalf("failed to find share: %v", err)
	}
	if found.ShareID != share1.ShareID {
		t.Error("wrong share returned for sender1")
	}

	found2, err := repo.GetByProviderID(ctx, "sender2.example.com", "same-id")
	if err != nil {
		t.Fatalf("failed to find share: %v", err)
	}
	if found2.ShareID != share2.ShareID {
		t.Error("wrong share returned for sender2")
	}
}

func TestExtractSenderHost(t *testing.T) {
	tests := []struct {
		sender   string
		expected string
	}{
		{"user@example.com", "example.com"},
		{"user@example.com:9200", "example.com:9200"},
		{"user@EXAMPLE.COM", "example.com"},
		{"invalid", ""},
	}

	for _, tt := range tests {
		t.Run(tt.sender, func(t *testing.T) {
			result := shares.ExtractSenderHost(tt.sender)
			if result != tt.expected {
				t.Errorf("ExtractSenderHost(%q) = %q, want %q", tt.sender, result, tt.expected)
			}
		})
	}
}
