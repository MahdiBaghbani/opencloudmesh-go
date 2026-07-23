package incoming_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

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
func newTestHandler(repo *sharesinbox.MemoryIncomingShareRepo, partyRepo identity.PartyRepo) *incoming.Handler {
	return newTestHandlerWithCodeFlow(repo, partyRepo, nil)
}

func newTestHandlerWithCodeFlow(
	repo *sharesinbox.MemoryIncomingShareRepo,
	partyRepo identity.PartyRepo,
	codeFlow *policy.CodeFlow,
) *incoming.Handler {
	return incoming.NewHandler(
		repo,
		partyRepo,
		nil, // no policy engine
		"localhost:9200",
		"https",
		codeFlow,
		testLogger(),
	)
}

func validShareBody(shareWith string) string {
	return validShareBodyWithHosts(shareWith, "sender.com")
}

func validShareBodyWithHosts(shareWith, ownerHost string) string {
	return validShareBodyWithOwnerAndSenderHosts(shareWith, ownerHost, ownerHost, "abc123")
}

func validShareBodyWithOwnerAndSenderHosts(shareWith, ownerHost, senderHost, providerID string) string {
	return `{
		"shareWith": "` + shareWith + `",
		"name": "test.txt",
		"providerId": "` + providerID + `",
		"owner": "owner@` + ownerHost + `",
		"sender": "sender@` + senderHost + `",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "webdav",
			"webdav": {
				"uri": "abc123",
				"sharedSecret": "secret123",
				"permissions": ["read"],
				"requirements": ["must-exchange-token"]
			}
		}
	}`
}

func newAcceptedShareHandler(
	t *testing.T,
	repo *sharesinbox.MemoryIncomingShareRepo,
	partyRepo identity.PartyRepo,
) (*incoming.Handler, string) {
	t.Helper()
	return newTestHandler(repo, partyRepo), "sender.com"
}

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

func TestCreateShare_Success_ResolvesById(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	body := validShareBodyWithHosts("user-a-uuid@localhost:9200", ownerHost)

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
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	body := validShareBodyWithHosts("alice@localhost:9200", ownerHost)
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
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	body := validShareBodyWithHosts("alice@example.org@localhost:9200", ownerHost)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_Authenticated_RejectsUntrustedOwnerProvider(t *testing.T) {
	const ownerHost = "owner.example.com"
	const senderHost = "relay.example.com"
	const providerID = "owner-sender-split"

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := validShareBodyWithOwnerAndSenderHosts("alice@localhost:9200", ownerHost, senderHost, providerID)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
		Authority:           senderHost,
		AuthorityForCompare: senderHost,
		Authenticated:       true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "UNTRUSTED_PROVIDER" {
		t.Errorf("expected UNTRUSTED_PROVIDER, got %q", resp.Message)
	}

	if _, err := repo.GetByProviderID(context.Background(), senderHost, providerID); err == nil {
		t.Fatal("expected no share persisted for untrusted owner provider")
	}
}

func TestCreateShare_MissingRequiredFields(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
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
	repo := sharesinbox.NewMemoryIncomingShareRepo()
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
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": ["must-exchange-token"]}}
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
	repo := sharesinbox.NewMemoryIncomingShareRepo()
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

func TestCreateShare_InvalidShareType_Returns501(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "p1",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "invalid",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": ["must-exchange-token"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for invalid shareType, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "SHARE_TYPE_NOT_SUPPORTED" {
		t.Errorf("expected SHARE_TYPE_NOT_SUPPORTED, got %q", resp.Message)
	}
}

func TestCreateShare_RecipientNotFound(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
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

func TestCreateShare_AuthenticatedIdentityOverridesRawSender(t *testing.T) {
	const authenticatedSender = "verified-sender.com"
	const rawSenderHost = "wrong-sender.com"
	const providerID = "auth-sender-override"

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()

	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "` + providerID + `",
		"owner": "owner@` + authenticatedSender + `",
		"sender": "user@` + rawSenderHost + `",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "webdav",
			"webdav": {
				"uri": "abc123",
				"sharedSecret": "secret123",
				"permissions": ["read"],
				"requirements": ["must-exchange-token"]
			}
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
		Authority:           authenticatedSender,
		AuthorityForCompare: authenticatedSender,
		Authenticated:       true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	stored, err := repo.GetByProviderID(context.Background(), authenticatedSender, providerID)
	if err != nil {
		t.Fatalf("expected share indexed by authenticated sender, got error: %v", err)
	}
	if stored.SenderHost != authenticatedSender {
		t.Fatalf("SenderHost = %q, want authenticated authority %q", stored.SenderHost, authenticatedSender)
	}

	if _, err := repo.GetByProviderID(context.Background(), rawSenderHost, providerID); err == nil {
		t.Fatal("expected share not indexed under raw sender host")
	}
}

func TestCreateShare_Authenticated_AcceptsDistinctOwnerAndSenderUserIDs(t *testing.T) {
	const authority = "relay.example.com"
	const providerID = "distinct-users-same-authority"

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "` + providerID + `",
		"owner": "owner-user@` + authority + `",
		"sender": "sender-user@` + authority + `",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "webdav",
			"webdav": {
				"uri": "abc123",
				"sharedSecret": "secret123",
				"permissions": ["read"],
				"requirements": ["must-exchange-token"]
			}
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
		Authority:           authority,
		AuthorityForCompare: authority,
		Authenticated:       true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	stored, err := repo.GetByProviderID(context.Background(), authority, providerID)
	if err != nil {
		t.Fatalf("expected persisted share, got error: %v", err)
	}
	if stored.OwnerHost != authority {
		t.Fatalf("OwnerHost = %q, want %q", stored.OwnerHost, authority)
	}
	if stored.SenderHost != authority {
		t.Fatalf("SenderHost = %q, want %q", stored.SenderHost, authority)
	}
	if stored.Owner == "sender-user@"+authority {
		t.Fatalf("expected distinct owner and sender user IDs, both %q", stored.Owner)
	}
	if stored.Sender == stored.Owner {
		t.Fatalf("expected distinct owner and sender addresses, both %q", stored.Owner)
	}
}

func TestCreateShare_DuplicateReturns200(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	body := validShareBodyWithHosts("alice@localhost:9200", ownerHost)

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

func TestCreateShare_InvalidResourceType_Returns501(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "rt-test",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "invalid",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": ["must-exchange-token"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for invalid resourceType, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_AcceptsFolderResourceType(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "folder",
		"providerId": "folder-test",
		"owner": "owner@` + ownerHost + `",
		"sender": "sender@` + ownerHost + `",
		"shareType": "user",
		"resourceType": "folder",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": ["must-exchange-token"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for folder resourceType, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_RejectsEmptyWebDAVFields(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing uri",
			body: `{
				"shareWith": "alice@localhost:9200",
				"name": "test.txt",
				"providerId": "wdav-empty-uri",
				"owner": "owner@sender.com",
				"sender": "sender@sender.com",
				"shareType": "user",
				"resourceType": "file",
				"protocol": {"name": "webdav", "webdav": {"sharedSecret": "s", "permissions": ["read"], "requirements": ["must-exchange-token"]}}
			}`,
		},
		{
			name: "missing sharedSecret",
			body: `{
				"shareWith": "alice@localhost:9200",
				"name": "test.txt",
				"providerId": "wdav-empty-secret",
				"owner": "owner@sender.com",
				"sender": "sender@sender.com",
				"shareType": "user",
				"resourceType": "file",
				"protocol": {"name": "webdav", "webdav": {"uri": "x", "permissions": ["read"], "requirements": ["must-exchange-token"]}}
			}`,
		},
		{
			name: "missing permissions",
			body: `{
				"shareWith": "alice@localhost:9200",
				"name": "test.txt",
				"providerId": "wdav-empty-perms",
				"owner": "owner@sender.com",
				"sender": "sender@sender.com",
				"shareType": "user",
				"resourceType": "file",
				"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "requirements": ["must-exchange-token"]}}
			}`,
		},
		{
			name: "empty requirements",
			body: `{
				"shareWith": "alice@localhost:9200",
				"name": "test.txt",
				"providerId": "wdav-empty-reqs",
				"owner": "owner@sender.com",
				"sender": "sender@sender.com",
				"shareType": "user",
				"resourceType": "file",
				"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": []}}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.CreateShare(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestCreateShare_RejectsUnsupportedWebDAVRequirement(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "wdav-bad-req",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": ["an-unsupported-requirement"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for unsupported webdav requirement, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_RejectsUnsupportedWebDAVPermissions(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "wdav-bad-perm",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["write"], "requirements": ["must-exchange-token"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for unsupported webdav permissions, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_RejectsUnsupportedWebDAVAccessTypes(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "wdav-bad-access",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "accessTypes": ["datatx"], "requirements": ["must-exchange-token"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for unsupported webdav accessTypes, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_MissingWebDAVArm_Returns400(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
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
		"protocol": {"name": "webdav"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing webdav arm, got %d: %s", w.Code, w.Body.String())
	}
}

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

func TestCreateShare_Success_ResolvesByFederatedOpaqueID(t *testing.T) {
	// Reva-style federated opaque ID: base64url_padded(userID@localProvider)
	// The encoded identifier won't match any user by raw ID, username, or email,
	// so triple resolution fails and the decode fallback fires.
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	encoded := base64.URLEncoding.EncodeToString([]byte("user-a-uuid@localhost:9200"))
	body := validShareBodyWithHosts(encoded+"@localhost:9200", ownerHost)

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for federated opaque ID, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.CreateShareResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.RecipientDisplayName != "Alice A" {
		t.Errorf("expected recipientDisplayName 'Alice A', got %q", resp.RecipientDisplayName)
	}
}

func TestCreateShare_FederatedOpaqueID_IDPMismatch_Rejected(t *testing.T) {
	// Encoded identifier decodes to a valid userID@idp payload, but the
	// decoded idp doesn't match local provider -- must be rejected.
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	encoded := base64.URLEncoding.EncodeToString([]byte("user-a-uuid@wrong-provider.com"))
	body := validShareBody(encoded + "@localhost:9200")

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for idp mismatch in decoded federated ID, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "RECIPIENT_NOT_FOUND" {
		t.Errorf("expected RECIPIENT_NOT_FOUND, got %q", resp.Message)
	}
}

func TestCreateShare_Base64LikeButNoFederatedPayload_Rejected(t *testing.T) {
	// "YWJj" is base64 of "abc" -- passes charset check but decoded payload
	// has no '@', so DecodeFederatedOpaqueID returns false. Falls through to
	// "recipient not found" since "YWJj" is not a real user.
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := validShareBody("YWJj@localhost:9200")

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for base64-like non-federated identifier, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "RECIPIENT_NOT_FOUND" {
		t.Errorf("expected RECIPIENT_NOT_FOUND, got %q", resp.Message)
	}
}

func shareBodyWithProtocolName(protocolName, ownerHost string) string {
	return `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "proto-name-test",
		"owner": "owner@` + ownerHost + `",
		"sender": "sender@` + ownerHost + `",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "` + protocolName + `",
			"webdav": {
				"uri": "abc123",
				"sharedSecret": "secret123",
				"permissions": ["read"],
				"requirements": ["must-exchange-token"]
			}
		}
	}`
}

func TestCreateShare_RejectsEmptyProtocolName(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "empty-proto",
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

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty protocol.name, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_InvalidProtocolName_Returns501(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(shareBodyWithProtocolName("invalid", "sender.com")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for invalid protocol name, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_AcceptsCanonicalWebDAVProtocolName(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(shareBodyWithProtocolName("webdav", ownerHost)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for canonical webdav protocol name, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_AcceptsMultiProtocolName(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(shareBodyWithProtocolName("multi", ownerHost)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for multi protocol name, got %d: %s", w.Code, w.Body.String())
	}
}

// validWebappShareBody builds a valid multi+webapp share request (no webdav
// arm) targeting the given recipient and using ownerHost for owner+sender.
func validWebappShareBody(shareWith, ownerHost, providerID string) string {
	return `{
		"shareWith": "` + shareWith + `",
		"name": "webapp-resource",
		"providerId": "` + providerID + `",
		"owner": "owner@` + ownerHost + `",
		"sender": "sender@` + ownerHost + `",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "multi",
			"webapp": {
				"uri": "https://` + ownerHost + `/apps/files/abc",
				"targets": ["blank"],
				"permissions": ["view", "read"],
				"requirements": ["must-exchange-token"],
				"sharedSecret": "secret123"
			}
		}
	}`
}

func TestCreateShare_AcceptsValidMultiWebapp(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	body := validWebappShareBody("alice@localhost:9200", ownerHost, "webapp-ok")
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for valid multi+webapp admit, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.CreateShareResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.RecipientDisplayName != "Alice A" {
		t.Errorf("expected recipientDisplayName 'Alice A', got %q", resp.RecipientDisplayName)
	}

	stored, err := repo.GetByProviderID(context.Background(), ownerHost, "webapp-ok")
	if err != nil {
		t.Fatalf("expected persisted share, got error: %v", err)
	}
	if stored.WebDAVID != "" || stored.SharedSecret != "" {
		t.Errorf("webapp-only admit must not populate WebDAV fields, got WebDAVID=%q SharedSecret=%q", stored.WebDAVID, stored.SharedSecret)
	}
	if stored.ProtocolName != "multi" {
		t.Errorf("ProtocolName = %q, want %q", stored.ProtocolName, "multi")
	}
	wantURI := "https://" + ownerHost + "/apps/files/abc"
	if stored.WebappURI != wantURI {
		t.Errorf("WebappURI = %q, want %q", stored.WebappURI, wantURI)
	}
	if len(stored.WebappTargets) != 1 || stored.WebappTargets[0] != "blank" {
		t.Errorf("WebappTargets = %v, want [blank]", stored.WebappTargets)
	}
	if len(stored.WebappPermissions) != 2 || stored.WebappPermissions[0] != "view" || stored.WebappPermissions[1] != "read" {
		t.Errorf("WebappPermissions = %v, want [view read]", stored.WebappPermissions)
	}
}

func TestCreateShare_RejectsWebappMissingURI(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "webapp-resource",
		"providerId": "webapp-no-uri",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "multi",
			"webapp": {
				"targets": ["blank"],
				"permissions": ["view"],
				"requirements": ["must-exchange-token"],
				"sharedSecret": "s"
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing webapp uri, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "protocol.webapp.uri" && e.Message == "REQUIRED" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected validationError {protocol.webapp.uri, REQUIRED}, got %v", resp.ValidationErrors)
	}
}

func TestCreateShare_RejectsWebappMissingTargets(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "webapp-resource",
		"providerId": "webapp-no-targets",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "multi",
			"webapp": {
				"uri": "https://sender.example/apps/files/abc",
				"permissions": ["view"],
				"requirements": ["must-exchange-token"],
				"sharedSecret": "s"
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing webapp targets, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "protocol.webapp.targets" && e.Message == "REQUIRED" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected validationError {protocol.webapp.targets, REQUIRED}, got %v", resp.ValidationErrors)
	}
}

func TestCreateShare_RejectsWebappMissingPermissions(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "webapp-resource",
		"providerId": "webapp-no-perms",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "multi",
			"webapp": {
				"uri": "https://sender.example/apps/files/abc",
				"targets": ["blank"],
				"requirements": ["must-exchange-token"],
				"sharedSecret": "s"
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing webapp permissions, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "protocol.webapp.permissions" && e.Message == "REQUIRED" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected validationError {protocol.webapp.permissions, REQUIRED}, got %v", resp.ValidationErrors)
	}
}

func TestCreateShare_RejectsWebappMissingSharedSecret(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "webapp-resource",
		"providerId": "webapp-no-secret",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "multi",
			"webapp": {
				"uri": "https://sender.example/apps/files/abc",
				"targets": ["blank"],
				"permissions": ["view"],
				"requirements": ["must-exchange-token"]
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing webapp sharedSecret, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "protocol.webapp.sharedSecret" && e.Message == "REQUIRED" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected validationError {protocol.webapp.sharedSecret, REQUIRED}, got %v", resp.ValidationErrors)
	}
}

func TestCreateShare_RejectsWebappUnsupportedPermission(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "webapp-resource",
		"providerId": "webapp-bad-perm",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "multi",
			"webapp": {
				"uri": "https://sender.example/apps/files/abc",
				"targets": ["blank"],
				"permissions": ["delete"],
				"requirements": ["must-exchange-token"],
				"sharedSecret": "s"
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for unsupported webapp permission, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "PROTOCOL_NOT_SUPPORTED" {
		t.Errorf("expected PROTOCOL_NOT_SUPPORTED, got %q", resp.Message)
	}
}

func TestCreateShare_RejectsWebappMustUseMFAWithGapNote(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "webapp-resource",
		"providerId": "webapp-mfa",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "multi",
			"webapp": {
				"uri": "https://sender.example/apps/files/abc",
				"targets": ["blank"],
				"permissions": ["view"],
				"requirements": ["must-exchange-token", "must-use-mfa"],
				"sharedSecret": "s"
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for must-use-mfa GAP rejection, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	var gapErr *spec.ValidationError
	for i := range resp.ValidationErrors {
		if resp.ValidationErrors[i].Name == "protocol.webapp.requirements" &&
			strings.Contains(resp.ValidationErrors[i].Message, "GAP") {
			gapErr = &resp.ValidationErrors[i]
			break
		}
	}
	if gapErr == nil {
		t.Fatalf("expected a GAP-bearing requirements validationError, got %v", resp.ValidationErrors)
	}
	if !strings.Contains(gapErr.Message, "enforce-mfa") {
		t.Errorf("GAP error should explain enforce-mfa is not implemented, got %q", gapErr.Message)
	}
}

func TestCreateShare_RejectsWebappMissingMustExchangeToken(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "webapp-resource",
		"providerId": "webapp-no-token",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "multi",
			"webapp": {
				"uri": "https://sender.example/apps/files/abc",
				"targets": ["blank"],
				"permissions": ["view"],
				"requirements": [],
				"sharedSecret": "s"
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing must-exchange-token, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "protocol.webapp.requirements" && e.Message == "REQUIRED" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected validationError {protocol.webapp.requirements, REQUIRED}, got %v", resp.ValidationErrors)
	}
}

func TestCreateShare_RejectsWebappUnknownRequirement(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "webapp-resource",
		"providerId": "webapp-bad-req",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "multi",
			"webapp": {
				"uri": "https://sender.example/apps/files/abc",
				"targets": ["blank"],
				"permissions": ["view"],
				"requirements": ["must-exchange-token", "an-unsupported-requirement"],
				"sharedSecret": "s"
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for unknown webapp requirement, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "PROTOCOL_NOT_SUPPORTED" {
		t.Errorf("expected PROTOCOL_NOT_SUPPORTED, got %q", resp.Message)
	}
}

func TestCreateShare_NilCodeFlow_RejectsEmptyWebDAVRequirements(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "nil-wdav-empty",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": []}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_NilCodeFlow_RejectsEmptyWebappRequirements(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "nil-wapp-empty",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "multi", "webapp": {"uri": "https://sender.com/apps/files/abc", "targets": ["blank"], "permissions": ["view"], "requirements": [], "sharedSecret": "s"}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	if len(resp.ValidationErrors) != 1 {
		t.Fatalf("expected exactly one validation error, got %d: %v", len(resp.ValidationErrors), resp.ValidationErrors)
	}
	if resp.ValidationErrors[0].Name != "protocol.webapp.requirements" || resp.ValidationErrors[0].Message != "REQUIRED" {
		t.Errorf("expected {protocol.webapp.requirements, REQUIRED}, got %v", resp.ValidationErrors[0])
	}
}

func TestCreateShare_NonNilZeroCodeFlow_RejectsEmptyWebDAVRequirementsUnderStrictAdmission(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandlerWithCodeFlow(repo, partyRepo, &policy.CodeFlow{})

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "nonnil-wdav-empty",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": []}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	if len(resp.ValidationErrors) != 1 {
		t.Fatalf("expected exactly one validation error, got %d: %v", len(resp.ValidationErrors), resp.ValidationErrors)
	}
	if resp.ValidationErrors[0].Name != "protocol.webdav.requirements" || resp.ValidationErrors[0].Message != "REQUIRED" {
		t.Errorf("expected {protocol.webdav.requirements, REQUIRED}, got %v", resp.ValidationErrors[0])
	}
}

func TestCreateShare_NilCodeFlow_AcceptsWebDAVWithMustExchangeToken(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "nil-wdav-token",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": ["must-exchange-token"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}
