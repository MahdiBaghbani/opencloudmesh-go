package incoming_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

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
