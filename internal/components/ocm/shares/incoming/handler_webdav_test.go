package incoming_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
)

func TestCreateShare_RejectsEmptyWebDAVFields(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
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
	repo := incoming.NewMemoryIncomingShareRepo()
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
	repo := incoming.NewMemoryIncomingShareRepo()
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
	repo := incoming.NewMemoryIncomingShareRepo()
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
	repo := incoming.NewMemoryIncomingShareRepo()
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
		name        string
		sender      string
		scheme      string
		expected    string
		expectError bool
	}{
		{"simple address", "user@example.com", "https", "example.com", false},
		{"with port", "user@example.com:9200", "https", "example.com:9200", false},
		{"uppercase host", "user@EXAMPLE.COM", "https", "example.com", false},
		{"default port stripped", "user@example.com:443", "https", "example.com", false},
		{"no @ separator", "invalid", "https", "", true},
		{"empty string", "", "https", "", true},
		{"email identifier (last-@)", "alice@university.edu@provider.net", "https", "provider.net", false},
		{"email identifier with port (last-@)", "alice@uni.edu@provider.net:443", "https", "provider.net", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := incoming.ExtractSenderHost(tt.sender, tt.scheme)
			if tt.expectError {
				if err == nil {
					t.Errorf("ExtractSenderHost(%q) expected error, got %q", tt.sender, result)
				}

				return
			}

			if err != nil {
				t.Fatalf("ExtractSenderHost(%q) unexpected error: %v", tt.sender, err)
			}

			if result != tt.expected {
				t.Errorf("ExtractSenderHost(%q) = %q, want %q", tt.sender, result, tt.expected)
			}
		})
	}
}
