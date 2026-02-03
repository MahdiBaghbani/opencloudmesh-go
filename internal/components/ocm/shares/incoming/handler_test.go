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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
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
func newTestHandler(repo *shares.MemoryIncomingShareRepo, partyRepo identity.PartyRepo) *incoming.Handler {
	return incoming.NewHandler(
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
	req := &spec.NewShareRequest{}
	errs := spec.ValidateRequiredFields(req)

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
	req := &spec.NewShareRequest{
		ShareWith:    "user@host",
		Name:         "file.txt",
		ProviderID:   "p1",
		Owner:        "o@h",
		Sender:       "s@h",
		ShareType:    "user",
		ResourceType: "file",
		Protocol:     spec.Protocol{Name: "webdav", WebDAV: &spec.WebDAVProtocol{URI: "x"}},
	}
	errs := spec.ValidateRequiredFields(req)
	if len(errs) != 0 {
		t.Errorf("expected no validation errors, got %d", len(errs))
	}
}

func TestValidateRequiredFields_ProtocolWithOnlyWebDAV(t *testing.T) {
	// Protocol has WebDAV but no name -- should not trigger "protocol REQUIRED"
	req := &spec.NewShareRequest{
		ShareWith:    "user@host",
		Name:         "file.txt",
		ProviderID:   "p1",
		Owner:        "o@h",
		Sender:       "s@h",
		ShareType:    "user",
		ResourceType: "file",
		Protocol:     spec.Protocol{WebDAV: &spec.WebDAVProtocol{URI: "x"}},
	}
	errs := spec.ValidateRequiredFields(req)
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

	var resp spec.CreateShareResponse
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

	var resp spec.CreateShareResponse
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

	var resp spec.OCMErrorResponse
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

	var resp spec.OCMErrorResponse
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

	var resp spec.OCMErrorResponse
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

	var resp spec.OCMErrorResponse
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

	var resp spec.OCMErrorResponse
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

	var resp spec.CreateShareResponse
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
			result := incoming.ExtractSenderHost(tt.sender)
			if result != tt.expected {
				t.Errorf("ExtractSenderHost(%q) = %q, want %q", tt.sender, result, tt.expected)
			}
		})
	}
}
