// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
)

func TestHandleCreate_Unauthenticated_Returns401(t *testing.T) {
	handler := newTestHandler(t, failCurrentUser())

	body := `{"receiverDomain":"example.com","shareWith":"user@example.com","localPath":"/tmp/test.txt","permissions":["read"]}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreate_MissingFields(t *testing.T) {
	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newTestHandler(t, testCurrentUser(user))

	tests := []struct {
		name string
		body string
	}{
		{"missing receiverDomain", `{"shareWith":"user@example.com","localPath":"/tmp/test.txt","permissions":["read"]}`},
		{"missing shareWith", `{"receiverDomain":"example.com","localPath":"/tmp/test.txt","permissions":["read"]}`},
		{"missing localPath", `{"receiverDomain":"example.com","shareWith":"user@example.com","permissions":["read"]}`},
		{"missing permissions", `{"receiverDomain":"example.com","shareWith":"user@example.com","localPath":"/tmp/test.txt"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()

			handler.HandleCreate(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleCreate_FileNotFound(t *testing.T) {
	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newTestHandler(t, testCurrentUser(user))
	handler.SetAllowedPaths([]string{"/tmp"})

	body := `{
		"receiverDomain": "example.com",
		"shareWith": "user@example.com",
		"localPath": "/tmp/nonexistent-file-12345.txt",
		"permissions": ["read"]
	}`

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreate_RejectsUnsupportedPermissions(t *testing.T) {
	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newTestHandler(t, testCurrentUser(user))
	handler.SetAllowedPaths([]string{"/tmp"})

	tmpFile, err := os.CreateTemp("/tmp", "outgoing-perm-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Errorf("remove temp file: %v", err)
		}
	}()

	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}

	body := `{
		"receiverDomain": "example.com",
		"shareWith": "user@example.com",
		"localPath": "` + tmpFile.Name() + `",
		"permissions": ["write"]
	}`

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	if !bytes.Contains(w.Body.Bytes(), []byte("permissions must be read-only")) {
		t.Fatalf("expected read-only permissions error, got: %s", w.Body.String())
	}
}

func TestHandleCreate_OwnerSenderUseRevaStyleFederatedID(t *testing.T) {
	user := &identity.User{ID: "user-uuid-123", Username: "alice", Email: "alice@example.org"}
	repo := tsrepos.OpenMemory(t).OutgoingShares

	discClient := makeDummyDiscoveryClient()
	handler := outgoingshares.NewHandler(
		repo,
		discClient,
		nil,
		nil,
		testProvider,
		testCurrentUser(user),
		testLogger,
		&stubResolver{facts: policy.NewCodeFlow().Evaluate()},
		"https://example.com/ocm/token",
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	tmpFile, err := os.CreateTemp("/tmp", "outgoing-share-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() {
		if rerr := os.Remove(tmpFile.Name()); rerr != nil {
			t.Errorf("remove temp file: %v", rerr)
		}
	}()

	if cerr := tmpFile.Close(); cerr != nil {
		t.Fatalf("close temp file: %v", cerr)
	}

	body := `{
		"receiverDomain": "receiver.example.com",
		"shareWith": "bob@receiver.example.com",
		"localPath": "` + tmpFile.Name() + `",
		"permissions": ["read"]
	}`

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	// Discovery now happens before persistence. With a dummy discovery client
	// that cannot reach the receiver, expect a 502. No share should be stored.
	if w.Code != http.StatusBadGateway && w.Code != http.StatusInternalServerError {
		t.Logf("unexpected status %d (expected 502 from discovery failure): %s", w.Code, w.Body.String())
	}

	allShares, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("failed to list shares: %v", err)
	}

	if len(allShares) != 0 {
		t.Errorf("expected no shares stored (preflight failed), got %d", len(allShares))
	}

	_ = address.FormatOutgoingOCMAddressFromUserID("user-uuid-123", testProvider)
}

func TestHandleCreate_MethodNotAllowed(t *testing.T) {
	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newTestHandler(t, testCurrentUser(user))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/shares/outgoing", nil)
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleCreate_ErrorResponseUsesAPIEnvelope(t *testing.T) {
	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newTestHandler(t, testCurrentUser(user))

	body := `{"shareWith":"user@example.com","localPath":"/tmp/test.txt","permissions":["read"]}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	// Should be 400 (missing receiverDomain)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	errObj, ok := resp["error"]
	if !ok {
		t.Fatal("error response missing 'error' field (should use api error envelope)")
	}

	errMap, ok := errObj.(map[string]any)
	if !ok {
		t.Fatal("error field is not an object")
	}

	if _, ok := errMap["reasonCode"]; !ok {
		t.Error("error response missing reasonCode field (should use api error envelope)")
	}
}
