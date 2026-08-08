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

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"
)

func TestCreateShare_RejectsEmptyWebDAVFields(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
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
			t.Parallel()

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(tt.body))
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
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
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
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for unsupported webdav requirement, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_RejectsUnsupportedWebDAVPermissions(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
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
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for unsupported webdav permissions, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_RejectsUnsupportedWebDAVAccessTypes(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
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
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for unsupported webdav accessTypes, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_MissingWebDAVArm_Returns400(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
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
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing webdav arm, got %d: %s", w.Code, w.Body.String())
	}
}
