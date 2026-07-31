// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
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
	repo := incoming.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo(t)
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
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty protocol.name, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_InvalidProtocolName_Returns501(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo(t)
	handler := newTestHandler(repo, partyRepo)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(shareBodyWithProtocolName("invalid", "sender.com")))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for invalid protocol name, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_AcceptsCanonicalWebDAVProtocolName(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo(t)
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(shareBodyWithProtocolName("webdav", ownerHost)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for canonical webdav protocol name, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_AcceptsMultiProtocolName(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo(t)
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(shareBodyWithProtocolName("multi", ownerHost)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for multi protocol name, got %d: %s", w.Code, w.Body.String())
	}
}
