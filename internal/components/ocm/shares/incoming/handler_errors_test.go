// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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

func TestCreateShare_MissingRequiredFields(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.Message != "MISSING_REQUIRED_FIELDS" {
		t.Errorf("expected message MISSING_REQUIRED_FIELDS, got %q", resp.Message)
	}

	if len(resp.ValidationErrors) == 0 {
		t.Error("expected validation errors in response")
	}
}

func TestCreateShare_InvalidOwnerFormat(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

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
	repo := incoming.NewMemoryIncomingShareRepo()
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.Message != "PROVIDER_MISMATCH" {
		t.Errorf("expected PROVIDER_MISMATCH, got %q", resp.Message)
	}
}

func TestCreateShare_InvalidShareType_Returns501(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.Message != "SHARE_TYPE_NOT_SUPPORTED" {
		t.Errorf("expected SHARE_TYPE_NOT_SUPPORTED, got %q", resp.Message)
	}
}

func TestCreateShare_RecipientNotFound(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

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
func TestCreateShare_InvalidResourceType_Returns501(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
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
func TestCreateShare_FederatedOpaqueID_IDPMismatch_Rejected(t *testing.T) {
	// Encoded identifier decodes to a valid userID@idp payload, but the
	// decoded idp doesn't match local provider -- must be rejected.
	repo := incoming.NewMemoryIncomingShareRepo()
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.Message != "RECIPIENT_NOT_FOUND" {
		t.Errorf("expected RECIPIENT_NOT_FOUND, got %q", resp.Message)
	}
}

func TestCreateShare_Base64LikeButNoFederatedPayload_Rejected(t *testing.T) {
	// "YWJj" is base64 of "abc" -- passes charset check but decoded payload
	// has no '@', so DecodeFederatedOpaqueID returns false. Falls through to
	// "recipient not found" since "YWJj" is not a real user.
	repo := incoming.NewMemoryIncomingShareRepo()
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.Message != "RECIPIENT_NOT_FOUND" {
		t.Errorf("expected RECIPIENT_NOT_FOUND, got %q", resp.Message)
	}
}
