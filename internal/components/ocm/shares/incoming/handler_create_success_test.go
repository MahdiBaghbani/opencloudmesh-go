package incoming_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestCreateShare_Success_ResolvesById(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.RecipientDisplayName != "Alice A" {
		t.Errorf("expected recipientDisplayName 'Alice A', got %q", resp.RecipientDisplayName)
	}
}

func TestCreateShare_Success_ResolvesByUsername(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.RecipientDisplayName != "Alice A" {
		t.Errorf("expected recipientDisplayName 'Alice A', got %q", resp.RecipientDisplayName)
	}
}

func TestCreateShare_Success_ResolvesByEmail(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
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
func TestCreateShare_DuplicateReturns200(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
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

	// Second request with same providerID + sender: 200 (idempotent)
	req2 := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req2.Header.Set("Content-Type", "application/json")

	w2 := httptest.NewRecorder()
	handler.CreateShare(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("duplicate request: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var resp spec.CreateShareResponse
	if err := json.NewDecoder(w2.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.RecipientDisplayName != "Alice A" {
		t.Errorf("duplicate response: expected recipientDisplayName 'Alice A', got %q", resp.RecipientDisplayName)
	}
}

func TestCreateShare_AcceptsFolderResourceType(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
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
func TestCreateShare_Success_ResolvesByFederatedOpaqueID(t *testing.T) {
	// Reva-style federated opaque ID: base64url_padded(userID@localProvider)
	// The encoded identifier won't match any user by raw ID, username, or email,
	// so triple resolution fails and the decode fallback fires.
	repo := incoming.NewMemoryIncomingShareRepo()
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.RecipientDisplayName != "Alice A" {
		t.Errorf("expected recipientDisplayName 'Alice A', got %q", resp.RecipientDisplayName)
	}
}
