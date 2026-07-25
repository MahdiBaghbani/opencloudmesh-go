package incoming_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
)

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
