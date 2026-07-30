package incoming_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// assertShareNotStored fails the test if the share identified by (senderHost,
// providerID) is present in the repo, or if the lookup returns an error other
// than ErrShareNotFound. A rejected admit must not persist; a silent lookup
// error must not be swallowed.
func assertShareNotStored(t *testing.T, repo *incoming.MemoryIncomingShareRepo, senderHost, providerID string) {
	t.Helper()

	stored, err := repo.GetByProviderID(context.Background(), senderHost, providerID)
	if err == nil && stored != nil {
		t.Errorf("share %q from %q must not be persisted, got %+v", providerID, senderHost, stored)
		return
	}

	if err != nil && !errors.Is(err, incoming.ErrShareNotFound) {
		t.Fatalf("unexpected lookup error for share %q from %q: %v", providerID, senderHost, err)
	}
}

func TestCreateShare_RejectsValidMultiWebapp(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	body := validWebappShareBody("alice@localhost:9200", ownerHost, "webapp-reject")
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for valid multi+webapp admit, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if resp.Message != "PROTOCOL_NOT_SUPPORTED" {
		t.Errorf("expected PROTOCOL_NOT_SUPPORTED, got %q", resp.Message)
	}

	assertShareNotStored(t, repo, ownerHost, "webapp-reject")
}

// TestCreateShare_RejectsMultiArmWithWebappAndWebDAV covers the 501-at-admit
// path when a share carries both a valid webdav arm and a valid webapp arm.
// ocmgo does not support inbound webapp receive, so the webapp arm must
// trigger 501 at admit regardless of a co-present webdav arm, and no share
// may be persisted.
func TestCreateShare_RejectsMultiArmWithWebappAndWebDAV(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "multi-arm-resource",
		"providerId": "multi-arm-webapp-reject",
		"owner": "owner@` + ownerHost + `",
		"sender": "sender@` + ownerHost + `",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "multi",
			"webdav": {
				"uri": "abc123",
				"sharedSecret": "secret123",
				"permissions": ["read"],
				"requirements": ["must-exchange-token"]
			},
			"webapp": {
				"uri": "https://` + ownerHost + `/apps/files/abc",
				"targets": ["blank"],
				"permissions": ["view", "read"],
				"requirements": ["must-exchange-token"],
				"sharedSecret": "secret123"
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for multi-arm admit with webapp, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if resp.Message != "PROTOCOL_NOT_SUPPORTED" {
		t.Errorf("expected PROTOCOL_NOT_SUPPORTED, got %q", resp.Message)
	}

	assertShareNotStored(t, repo, ownerHost, "multi-arm-webapp-reject")
}

func TestCreateShare_RejectsWebappMissingURI(t *testing.T) { //nolint:dupl // intentional: parallel webapp validation tests share error-check structure but assert different missing fields
	repo := incoming.NewMemoryIncomingShareRepo()
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

func TestCreateShare_RejectsWebappMissingTargets(t *testing.T) { //nolint:dupl // intentional: parallel webapp validation tests share error-check structure but assert different missing fields
	repo := incoming.NewMemoryIncomingShareRepo()
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

func TestCreateShare_RejectsWebappMissingPermissions(t *testing.T) { //nolint:dupl // intentional: parallel webapp validation tests share error-check structure but assert different missing fields
	repo := incoming.NewMemoryIncomingShareRepo()
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

func TestCreateShare_RejectsWebappMissingSharedSecret(t *testing.T) { //nolint:dupl // intentional: parallel webapp validation tests share error-check structure but assert different missing fields
	repo := incoming.NewMemoryIncomingShareRepo()
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
	repo := incoming.NewMemoryIncomingShareRepo()
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
	repo := incoming.NewMemoryIncomingShareRepo()
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
		t.Fatalf("expected 400 for must-use-mfa rejection, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}

	wantMsg := "must-use-mfa rejected at admit; MFA enforcement is not supported"

	var mfaErr *spec.ValidationError

	for i := range resp.ValidationErrors {
		if resp.ValidationErrors[i].Name == "protocol.webapp.requirements" &&
			resp.ValidationErrors[i].Message == wantMsg {
			mfaErr = &resp.ValidationErrors[i]
			break
		}
	}

	if mfaErr == nil {
		t.Fatalf("expected requirements validationError %q, got %v", wantMsg, resp.ValidationErrors)
	}
}

func TestCreateShare_RejectsWebappMissingMustExchangeToken(t *testing.T) { //nolint:dupl // intentional: parallel webapp validation tests share error-check structure but assert different missing fields
	repo := incoming.NewMemoryIncomingShareRepo()
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
	repo := incoming.NewMemoryIncomingShareRepo()
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
