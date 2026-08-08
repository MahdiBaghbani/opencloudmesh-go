// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// assertShareNotStored fails the test if the share identified by (senderHost,
// providerID) is present in the repo, or if the lookup returns an error other
// than ErrShareNotFound. A rejected admit must not persist; a silent lookup
// error must not be swallowed.
func assertShareNotStored(t *testing.T, repo incoming.IncomingShareRepo, senderHost, providerID string) {
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
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	body := validWebappShareBody("alice@localhost:9200", ownerHost, "webapp-reject")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
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
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
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
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
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

func TestCreateShare_RejectsWebappMissingFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		fieldName string
		failMsg   string
	}{
		{
			name: "MissingURI",
			body: `{
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
	}`,
			fieldName: "protocol.webapp.uri",
			failMsg:   "expected 400 for missing webapp uri",
		},
		{
			name: "MissingTargets",
			body: `{
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
	}`,
			fieldName: "protocol.webapp.targets",
			failMsg:   "expected 400 for missing webapp targets",
		},
		{
			name: "MissingPermissions",
			body: `{
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
	}`,
			fieldName: "protocol.webapp.permissions",
			failMsg:   "expected 400 for missing webapp permissions",
		},
		{
			name: "MissingSharedSecret",
			body: `{
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
	}`,
			fieldName: "protocol.webapp.sharedSecret",
			failMsg:   "expected 400 for missing webapp sharedSecret",
		},
		{
			name: "MissingMustExchangeToken",
			body: `{
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
	}`,
			fieldName: "protocol.webapp.requirements",
			failMsg:   "expected 400 for missing must-exchange-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repo := tsrepos.OpenMemory(t).IncomingShares
			partyRepo := setupTestPartyRepo(t)
			handler := newTestHandler(repo, partyRepo)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			handler.CreateShare(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s, got %d: %s", tt.failMsg, w.Code, w.Body.String())
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
				if e.Name == tt.fieldName && e.Message == "REQUIRED" {
					found = true
				}
			}

			if !found {
				t.Errorf("expected validationError {%s, REQUIRED}, got %v", tt.fieldName, resp.ValidationErrors)
			}
		})
	}
}

func TestCreateShare_RejectsWebappUnsupportedPermission(t *testing.T) {
	t.Parallel()

	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
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
	bodyReader := bytes.NewBufferString(body)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bodyReader)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for unsupported webapp permission, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	const wantMessage = "PROTOCOL_NOT_SUPPORTED"
	if resp.Message != wantMessage {
		t.Errorf("expected %s, got %q", wantMessage, resp.Message)
	}
}

func TestCreateShare_RejectsWebappMustUseMFAWithGapNote(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
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
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
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

func TestCreateShare_RejectsWebappUnknownRequirement(t *testing.T) {
	t.Parallel()

	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
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
	bodyReader := bytes.NewBufferString(body)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bodyReader)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for unknown webapp requirement, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if got := resp.Message; got != "PROTOCOL_NOT_SUPPORTED" {
		t.Errorf("expected PROTOCOL_NOT_SUPPORTED, got %q", got)
	}
}
