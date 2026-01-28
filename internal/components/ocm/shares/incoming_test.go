package shares_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
)

// testLogger returns a quiet logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

// setupTestPartyRepo creates a PartyRepo with test users.
func setupTestPartyRepo() identity.PartyRepo {
	repo := identity.NewMemoryPartyRepo()
	ctx := context.Background()
	repo.Create(ctx, &identity.User{
		ID:          "user-a-uuid",
		Username:    "alice",
		Email:       "alice@example.org",
		DisplayName: "Alice A",
	})
	repo.Create(ctx, &identity.User{
		ID:          "user-b-uuid",
		Username:    "bob",
		Email:       "bob@example.org",
		DisplayName: "Bob B",
	})
	return repo
}

// newTestHandler creates a handler wired for testing against localhost:9200 (https).
func newTestHandler(repo *shares.MemoryIncomingShareRepo, partyRepo identity.PartyRepo) *shares.IncomingHandler {
	return shares.NewIncomingHandler(
		repo,
		partyRepo,
		nil, // no policy engine
		"localhost:9200",
		"https",
		"strict",
		testLogger(),
	)
}

func validShareBody(shareWith string) string {
	return `{
		"shareWith": "` + shareWith + `",
		"name": "test.txt",
		"providerId": "abc123",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "webdav",
			"webdav": {
				"uri": "abc123",
				"sharedSecret": "secret123",
				"permissions": ["read"]
			}
		}
	}`
}

// --- ValidateRequiredFields ---

func TestValidateRequiredFields_AllMissing(t *testing.T) {
	req := &shares.NewShareRequest{}
	errs := shares.ValidateRequiredFields(req)

	if len(errs) == 0 {
		t.Fatal("expected validation errors for empty request")
	}

	names := map[string]bool{}
	for _, e := range errs {
		names[e.Name] = true
		if e.Message != "REQUIRED" {
			t.Errorf("expected message REQUIRED for field %s, got %s", e.Name, e.Message)
		}
	}

	required := []string{"shareWith", "name", "providerId", "owner", "sender", "shareType", "resourceType", "protocol"}
	for _, f := range required {
		if !names[f] {
			t.Errorf("expected validation error for field %s", f)
		}
	}
}

func TestValidateRequiredFields_AllPresent(t *testing.T) {
	req := &shares.NewShareRequest{
		ShareWith:    "user@host",
		Name:         "file.txt",
		ProviderID:   "p1",
		Owner:        "o@h",
		Sender:       "s@h",
		ShareType:    "user",
		ResourceType: "file",
		Protocol:     shares.Protocol{Name: "webdav", WebDAV: &shares.WebDAVProtocol{URI: "x"}},
	}
	errs := shares.ValidateRequiredFields(req)
	if len(errs) != 0 {
		t.Errorf("expected no validation errors, got %d", len(errs))
	}
}

func TestValidateRequiredFields_ProtocolWithOnlyWebDAV(t *testing.T) {
	// Protocol has WebDAV but no name -- should not trigger "protocol REQUIRED"
	req := &shares.NewShareRequest{
		ShareWith:    "user@host",
		Name:         "file.txt",
		ProviderID:   "p1",
		Owner:        "o@h",
		Sender:       "s@h",
		ShareType:    "user",
		ResourceType: "file",
		Protocol:     shares.Protocol{WebDAV: &shares.WebDAVProtocol{URI: "x"}},
	}
	errs := shares.ValidateRequiredFields(req)
	if len(errs) != 0 {
		t.Errorf("expected no validation errors for protocol with webdav, got %d: %v", len(errs), errs)
	}
}

// --- CreateShare handler ---

func TestCreateShare_Success_ResolvesById(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	// shareWith uses user ID as identifier
	body := validShareBody("user-a-uuid@localhost:9200")

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp shares.CreateShareResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.RecipientDisplayName != "Alice A" {
		t.Errorf("expected recipientDisplayName 'Alice A', got %q", resp.RecipientDisplayName)
	}
}

func TestCreateShare_Success_ResolvesByUsername(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := validShareBody("alice@localhost:9200")
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp shares.CreateShareResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.RecipientDisplayName != "Alice A" {
		t.Errorf("expected recipientDisplayName 'Alice A', got %q", resp.RecipientDisplayName)
	}
}

func TestCreateShare_Success_ResolvesByEmail(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	// Email contains @, so shareWith uses last-@ semantics
	body := validShareBody("alice@example.org@localhost:9200")
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_MissingRequiredFields(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{"name": "test.txt"}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp shares.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "MISSING_REQUIRED_FIELDS" {
		t.Errorf("expected message MISSING_REQUIRED_FIELDS, got %q", resp.Message)
	}
	if len(resp.ValidationErrors) == 0 {
		t.Error("expected validation errors in response")
	}
}

func TestCreateShare_InvalidOwnerFormat(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "p1",
		"owner": "invalid-no-at",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid owner, got %d: %s", w.Code, w.Body.String())
	}

	var resp shares.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "INVALID_FIELD_FORMAT" {
		t.Errorf("expected INVALID_FIELD_FORMAT, got %q", resp.Message)
	}

	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "owner" && e.Message == "INVALID_FORMAT" {
			found = true
		}
	}
	if !found {
		t.Error("expected validation error for owner with INVALID_FORMAT")
	}
}

func TestCreateShare_ProviderMismatch(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := validShareBody("alice@wrong-provider.com")
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for provider mismatch, got %d: %s", w.Code, w.Body.String())
	}

	var resp shares.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "PROVIDER_MISMATCH" {
		t.Errorf("expected PROVIDER_MISMATCH, got %q", resp.Message)
	}
}

func TestCreateShare_UnsupportedShareType_Returns501(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "p1",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "group",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for unsupported shareType, got %d: %s", w.Code, w.Body.String())
	}

	var resp shares.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "SHARE_TYPE_NOT_SUPPORTED" {
		t.Errorf("expected SHARE_TYPE_NOT_SUPPORTED, got %q", resp.Message)
	}
}

func TestCreateShare_RecipientNotFound(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := validShareBody("nonexistent@localhost:9200")
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown recipient (spec-mandated, not 404), got %d: %s", w.Code, w.Body.String())
	}

	var resp shares.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "RECIPIENT_NOT_FOUND" {
		t.Errorf("expected RECIPIENT_NOT_FOUND, got %q", resp.Message)
	}

	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "shareWith" && e.Message == "NOT_FOUND" {
			found = true
		}
	}
	if !found {
		t.Error("expected validationError {shareWith, NOT_FOUND}")
	}
}

func TestCreateShare_DuplicateReturns200(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := validShareBody("alice@localhost:9200")

	// First request: 201
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("first request: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Second request with same providerId + sender: 200 (idempotent)
	req2 := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler.CreateShare(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("duplicate request: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var resp shares.CreateShareResponse
	json.NewDecoder(w2.Body).Decode(&resp)
	if resp.RecipientDisplayName != "Alice A" {
		t.Errorf("duplicate response: expected recipientDisplayName 'Alice A', got %q", resp.RecipientDisplayName)
	}
}

func TestCreateShare_AcceptsAllResourceTypes(t *testing.T) {
	// F7=A: accept all resourceType values, do not reject unknown types
	repo := shares.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "rt-test",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "calendar",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for custom resourceType, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_NoWebDAV_Returns501(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "p1",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webapp"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for missing webdav, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Repository ---

func TestIncomingRepository_SenderScopedStorage(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	ctx := context.Background()

	share1 := &shares.IncomingShare{
		ProviderID:      "same-id",
		SenderHost:      "sender1.example.com",
		ShareWith:       "user@example.com",
		RecipientUserID: "user-a",
		Status:          shares.ShareStatusPending,
	}
	if err := repo.Create(ctx, share1); err != nil {
		t.Fatalf("failed to create share1: %v", err)
	}

	share2 := &shares.IncomingShare{
		ProviderID:      "same-id",
		SenderHost:      "sender2.example.com",
		ShareWith:       "user@example.com",
		RecipientUserID: "user-a",
		Status:          shares.ShareStatusPending,
	}
	if err := repo.Create(ctx, share2); err != nil {
		t.Fatalf("failed to create share2: %v", err)
	}

	// Duplicate from sender1 should fail
	share3 := &shares.IncomingShare{
		ProviderID:      "same-id",
		SenderHost:      "sender1.example.com",
		ShareWith:       "user@example.com",
		RecipientUserID: "user-a",
		Status:          shares.ShareStatusPending,
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
}

func TestIncomingRepository_RecipientScoping(t *testing.T) {
	repo := shares.NewMemoryIncomingShareRepo()
	ctx := context.Background()

	// Create shares for different recipients
	shareA := &shares.IncomingShare{
		ProviderID:      "p1",
		SenderHost:      "sender.com",
		RecipientUserID: "user-a",
		Status:          shares.ShareStatusPending,
	}
	repo.Create(ctx, shareA)

	shareB := &shares.IncomingShare{
		ProviderID:      "p2",
		SenderHost:      "sender.com",
		RecipientUserID: "user-b",
		Status:          shares.ShareStatusPending,
	}
	repo.Create(ctx, shareB)

	// User A should only see their share
	listA, _ := repo.ListByRecipientUserID(ctx, "user-a")
	if len(listA) != 1 {
		t.Fatalf("user-a: expected 1 share, got %d", len(listA))
	}
	if listA[0].ShareID != shareA.ShareID {
		t.Error("user-a: got wrong share")
	}

	// User B should only see their share
	listB, _ := repo.ListByRecipientUserID(ctx, "user-b")
	if len(listB) != 1 {
		t.Fatalf("user-b: expected 1 share, got %d", len(listB))
	}

	// User A cannot get user B's share
	_, err := repo.GetByIDForRecipientUserID(ctx, shareB.ShareID, "user-a")
	if err == nil {
		t.Error("expected error when user-a tries to access user-b's share")
	}

	// User A cannot update user B's share
	err = repo.UpdateStatusForRecipientUserID(ctx, shareB.ShareID, "user-a", shares.ShareStatusAccepted)
	if err == nil {
		t.Error("expected error when user-a tries to update user-b's share")
	}

	// User A cannot delete user B's share
	err = repo.DeleteForRecipientUserID(ctx, shareB.ShareID, "user-a")
	if err == nil {
		t.Error("expected error when user-a tries to delete user-b's share")
	}
}

// --- Validation helpers ---

func TestExtractSenderHost(t *testing.T) {
	tests := []struct {
		name     string
		sender   string
		expected string
	}{
		{"simple address", "user@example.com", "example.com"},
		{"with port", "user@example.com:9200", "example.com:9200"},
		{"uppercase host", "user@EXAMPLE.COM", "example.com"},
		{"no @ separator", "invalid", ""},
		{"empty string", "", ""},
		{"email identifier (last-@)", "alice@university.edu@provider.net", "provider.net"},
		{"email identifier with port (last-@)", "alice@uni.edu@provider.net:443", "provider.net:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shares.ExtractSenderHost(tt.sender)
			if result != tt.expected {
				t.Errorf("ExtractSenderHost(%q) = %q, want %q", tt.sender, result, tt.expected)
			}
		})
	}
}

func TestWebDAVProtocol_HasRequirement(t *testing.T) {
	p := &shares.WebDAVProtocol{
		URI:          "abc123",
		Permissions:  []string{"read"},
		Requirements: []string{"must-exchange-token"},
	}

	if !p.HasRequirement("must-exchange-token") {
		t.Error("expected true for must-exchange-token")
	}
	if p.HasRequirement("must-use-mfa") {
		t.Error("expected false for must-use-mfa")
	}
}
