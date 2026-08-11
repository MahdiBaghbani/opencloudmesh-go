// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func postCreateShare(t *testing.T, handler *incoming.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	return w
}

func assertCreateShareSuccess(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()

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

func assertShareConflict(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.Message != "SHARE_ALREADY_EXISTS_WITH_DIFFERENT_PAYLOAD" {
		t.Errorf("expected SHARE_ALREADY_EXISTS_WITH_DIFFERENT_PAYLOAD, got %q", resp.Message)
	}
}

func TestCreateShare_DuplicateIdenticalPayloadReturns201(t *testing.T) {
	t.Parallel()

	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	body := validShareBodyWithHosts("alice@localhost:9200", ownerHost)

	w := postCreateShare(t, handler, body)
	assertCreateShareSuccess(t, w)

	original, err := repo.GetByProviderID(context.Background(), ownerHost, "abc123")
	if err != nil {
		t.Fatalf("GetByProviderID: %v", err)
	}

	listBefore, err := repo.ListByRecipientUserID(context.Background(), "user-a-uuid")
	if err != nil {
		t.Fatalf("ListByRecipientUserID: %v", err)
	}

	if len(listBefore) != 1 {
		t.Fatalf("expected 1 stored share before duplicate, got %d", len(listBefore))
	}

	w2 := postCreateShare(t, handler, body)
	assertCreateShareSuccess(t, w2)

	listAfter, err := repo.ListByRecipientUserID(context.Background(), "user-a-uuid")
	if err != nil {
		t.Fatalf("ListByRecipientUserID: %v", err)
	}

	if len(listAfter) != 1 {
		t.Fatalf("expected 1 stored share after duplicate, got %d", len(listAfter))
	}

	stored, err := repo.GetByProviderID(context.Background(), ownerHost, "abc123")
	if err != nil {
		t.Fatalf("GetByProviderID after duplicate: %v", err)
	}

	if stored.ShareID != original.ShareID ||
		stored.WebDAVID != original.WebDAVID ||
		stored.SharedSecret != original.SharedSecret ||
		stored.Name != original.Name {
		t.Error("duplicate idempotent retry changed stored share material")
	}
}

func int64PtrChanged(a, b *int64) bool {
	if a == nil && b == nil {
		return false
	}

	if a == nil || b == nil {
		return true
	}

	return *a != *b
}

type duplicateMismatchCase struct {
	name       string
	setupFirst func(body string) string
	mutate     func(body string) string
	checkFn    func(t *testing.T, original, stored *incoming.IncomingShare)
}

func runDuplicateMismatchCase(t *testing.T, tc duplicateMismatchCase) {
	t.Helper()

	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	body := validShareBodyWithHosts("alice@localhost:9200", ownerHost)

	firstBody := body
	if tc.setupFirst != nil {
		firstBody = tc.setupFirst(body)
	}

	w := postCreateShare(t, handler, firstBody)
	assertCreateShareSuccess(t, w)

	original, err := repo.GetByProviderID(context.Background(), ownerHost, "abc123")
	if err != nil {
		t.Fatalf("GetByProviderID: %v", err)
	}

	wConflict := postCreateShare(t, handler, tc.mutate(body))
	assertShareConflict(t, wConflict)

	list, err := repo.ListByRecipientUserID(context.Background(), "user-a-uuid")
	if err != nil {
		t.Fatalf("ListByRecipientUserID: %v", err)
	}

	if len(list) != 1 {
		t.Fatalf("expected 1 stored share after conflict, got %d", len(list))
	}

	stored, err := repo.GetByProviderID(context.Background(), ownerHost, "abc123")
	if err != nil {
		t.Fatalf("GetByProviderID after conflict: %v", err)
	}

	if stored.ShareID != original.ShareID {
		t.Errorf("ShareID changed: got %q want %q", stored.ShareID, original.ShareID)
	}

	tc.checkFn(t, original, stored)
}

func TestCreateShare_DuplicateMismatchedPayloadReturns409(t *testing.T) {
	t.Parallel()

	cases := []duplicateMismatchCase{
		{
			name: "expiration",
			mutate: func(body string) string {
				return strings.Replace(body, `"resourceType": "file"`, `"resourceType": "file", "expiration": 1800000000`, 1)
			},
			setupFirst: func(body string) string {
				return strings.Replace(body, `"resourceType": "file"`, `"resourceType": "file", "expiration": 1700000000`, 1)
			},
			checkFn: func(t *testing.T, original, stored *incoming.IncomingShare) {
				t.Helper()

				if int64PtrChanged(stored.Expiration, original.Expiration) {
					t.Errorf("Expiration changed: got %v want %v", stored.Expiration, original.Expiration)
				}
			},
		},
		{
			name: "description",
			mutate: func(body string) string {
				return strings.Replace(body, `"name": "test.txt"`, `"name": "test.txt", "description": "changed"`, 1)
			},
			setupFirst: func(body string) string {
				return strings.Replace(body, `"name": "test.txt"`, `"name": "test.txt", "description": "notes"`, 1)
			},
			checkFn: func(t *testing.T, original, stored *incoming.IncomingShare) {
				t.Helper()

				if stored.Description != original.Description {
					t.Errorf("Description changed: got %q want %q", stored.Description, original.Description)
				}
			},
		},
		{
			name: "owner",
			mutate: func(body string) string {
				return strings.Replace(body, `"owner": "owner@`, `"owner": "other@`, 1)
			},
			setupFirst: nil,
			checkFn: func(t *testing.T, original, stored *incoming.IncomingShare) {
				t.Helper()

				if stored.Owner != original.Owner {
					t.Errorf("Owner changed: got %q want %q", stored.Owner, original.Owner)
				}
			},
		},
		{
			name: "sender",
			mutate: func(body string) string {
				return strings.Replace(body, `"sender": "sender@`, `"sender": "other@`, 1)
			},
			setupFirst: nil,
			checkFn: func(t *testing.T, original, stored *incoming.IncomingShare) {
				t.Helper()

				if stored.Sender != original.Sender {
					t.Errorf("Sender changed: got %q want %q", stored.Sender, original.Sender)
				}
			},
		},
		{
			name: "protocol name",
			mutate: func(body string) string {
				return strings.Replace(body, `"name": "webdav"`, `"name": "multi"`, 1)
			},
			setupFirst: nil,
			checkFn: func(t *testing.T, original, stored *incoming.IncomingShare) {
				t.Helper()

				if stored.ProtocolName != original.ProtocolName {
					t.Errorf("ProtocolName changed: got %q want %q", stored.ProtocolName, original.ProtocolName)
				}
			},
		},
		{
			name: "webdav uri",
			mutate: func(body string) string {
				return strings.Replace(body, `"uri": "abc123"`, `"uri": "changed-uri"`, 1)
			},
			checkFn: func(t *testing.T, original, stored *incoming.IncomingShare) {
				t.Helper()

				if stored.WebDAVID != original.WebDAVID {
					t.Errorf("WebDAVID changed: got %q want %q", stored.WebDAVID, original.WebDAVID)
				}
			},
		},
		{
			name: "shared secret",
			mutate: func(body string) string {
				return strings.Replace(body, `"sharedSecret": "secret123"`, `"sharedSecret": "other-secret"`, 1)
			},
			checkFn: func(t *testing.T, original, stored *incoming.IncomingShare) {
				t.Helper()

				if stored.SharedSecret != original.SharedSecret {
					t.Errorf("SharedSecret changed: got %q want %q", stored.SharedSecret, original.SharedSecret)
				}
			},
		},
		{
			name: "permissions",
			mutate: func(body string) string {
				return strings.Replace(body, `"permissions": ["read"]`, `"permissions": ["read", "read"]`, 1)
			},
			checkFn: func(t *testing.T, original, stored *incoming.IncomingShare) {
				t.Helper()

				if len(stored.Permissions) != len(original.Permissions) || stored.Permissions[0] != original.Permissions[0] {
					t.Errorf("Permissions changed: got %v want %v", stored.Permissions, original.Permissions)
				}
			},
		},
		{
			name: "name",
			mutate: func(body string) string {
				return strings.Replace(body, `"name": "test.txt"`, `"name": "other.txt"`, 1)
			},
			checkFn: func(t *testing.T, original, stored *incoming.IncomingShare) {
				t.Helper()

				if stored.Name != original.Name {
					t.Errorf("Name changed: got %q want %q", stored.Name, original.Name)
				}
			},
		},
		{
			name: "shareWith",
			mutate: func(body string) string {
				return strings.Replace(body, `"shareWith": "alice@localhost:9200"`, `"shareWith": "bob@localhost:9200"`, 1)
			},
			checkFn: func(t *testing.T, original, stored *incoming.IncomingShare) {
				t.Helper()

				if stored.ShareWith != original.ShareWith {
					t.Errorf("ShareWith changed: got %q want %q", stored.ShareWith, original.ShareWith)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			runDuplicateMismatchCase(t, tc)
		})
	}
}

func duplicatePayloadOrderFixture() (*incoming.IncomingShare, *spec.NewShareRequest) {
	expiration := int64(1700000000)

	existing := &incoming.IncomingShare{
		Name:         "test.txt",
		ResourceType: "file",
		ShareWith:    "alice@localhost:9200",
		ShareType:    "user",
		Owner:        "owner@sender.com",
		Sender:       "sender@sender.com",
		ProtocolName: "webdav",
		Description:  "notes",
		Expiration:   &expiration,
		WebDAVID:     "abc123",
		SharedSecret: "secret123",
		Permissions:  []string{"read", "write"},
		Requirements: []string{"must-exchange-token", "must-use-mfa"},
	}

	req := &spec.NewShareRequest{
		Name:         "test.txt",
		ResourceType: "file",
		ShareWith:    "alice@localhost:9200",
		ShareType:    "user",
		Owner:        "owner@sender.com",
		Sender:       "sender@sender.com",
		Description:  "notes",
		Expiration:   &expiration,
		Protocol: spec.Protocol{
			Name: "webdav",
			WebDAV: &spec.WebDAVProtocol{
				URI:          "abc123",
				SharedSecret: "secret123",
				Permissions:  []string{"read", "write"},
				Requirements: []string{"must-exchange-token", "must-use-mfa"},
			},
		},
	}

	return existing, req
}

func TestCreateShare_DuplicateReorderedPermissionsReturns409(t *testing.T) {
	t.Parallel()

	existing, req := duplicatePayloadOrderFixture()
	req.Protocol.WebDAV.Permissions = []string{"write", "read"}

	w := httptest.NewRecorder()
	resolvedUser := &identity.User{DisplayName: "Alice A"}

	if !incoming.HandleExistingIncomingShareForTest(w, slog.Default(), existing, req, "sender.com", resolvedUser) {
		t.Fatal("expected existing share to be handled")
	}

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_DuplicateReorderedRequirementsReturns409(t *testing.T) {
	t.Parallel()

	existing, req := duplicatePayloadOrderFixture()
	req.Protocol.WebDAV.Requirements = []string{"must-use-mfa", "must-exchange-token"}

	w := httptest.NewRecorder()
	resolvedUser := &identity.User{DisplayName: "Alice A"}

	if !incoming.HandleExistingIncomingShareForTest(w, slog.Default(), existing, req, "sender.com", resolvedUser) {
		t.Fatal("expected existing share to be handled")
	}

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_NewShareStillReturns201(t *testing.T) {
	t.Parallel()

	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	body := validShareBodyWithOwnerAndSenderHosts("alice@localhost:9200", ownerHost, ownerHost, "unique-provider-id")

	w := postCreateShare(t, handler, body)
	assertCreateShareSuccess(t, w)

	list, err := repo.ListByRecipientUserID(context.Background(), "user-a-uuid")
	if err != nil {
		t.Fatalf("ListByRecipientUserID: %v", err)
	}

	if len(list) != 1 {
		t.Fatalf("expected 1 stored share, got %d", len(list))
	}
}
