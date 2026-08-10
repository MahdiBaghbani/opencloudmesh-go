// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
)

func TestHandleCreate_RejectsPathWhenNoAllowedPathsConfigured(t *testing.T) {
	t.Parallel()

	user := testUser()
	handler := newTestHandler(t, testCurrentUser(user))

	body := `{
		"receiverDomain": "example.com",
		"shareWith": "user@example.com",
		"localPath": "/tmp/test.txt",
		"permissions": ["read"]
	}`

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	if !bytes.Contains(w.Body.Bytes(), []byte("path not in allowed directories")) {
		t.Fatalf("expected path allowlist error, got: %s", w.Body.String())
	}
}

func TestHandleCreate_RejectsPathOutsideAllowedDirectories(t *testing.T) {
	t.Parallel()

	user := testUser()
	handler := newTestHandler(t, testCurrentUser(user))
	handler.SetAllowedPaths([]string{"/tmp/ocm-content"})

	tests := []struct {
		name      string
		localPath string
	}{
		{name: "absolute outside root", localPath: "/etc/passwd"},
		{name: "sibling prefix", localPath: "/tmp/ocm-content-evil/share.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := outgoingCreateBody("example.com", tt.localPath)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			handler.HandleCreate(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}

			if !bytes.Contains(w.Body.Bytes(), []byte("path not in allowed directories")) {
				t.Fatalf("expected path allowlist error, got: %s", w.Body.String())
			}
		})
	}
}

func TestHandleCreate_AcceptsRelativePathUnderContentRoot(t *testing.T) { //nolint:paralleltest // uses t.Chdir
	t.Chdir(t.TempDir())

	contentRoot, err := filepath.Abs("content-root")
	if err != nil {
		t.Fatalf("Abs content root: %v", err)
	}

	if err := os.MkdirAll(contentRoot, 0700); err != nil {
		t.Fatalf("MkdirAll content root: %v", err)
	}

	sharePath := filepath.Join(contentRoot, "demo.txt")
	if err := os.WriteFile(sharePath, []byte("share me"), 0600); err != nil {
		t.Fatalf("write share file: %v", err)
	}

	user := testUser()
	handler := newTestHandler(t, testCurrentUser(user))
	handler.SetAllowedPaths([]string{contentRoot})

	body := outgoingCreateBody("example.com", "demo.txt")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if bytes.Contains(w.Body.Bytes(), []byte("path not in allowed directories")) {
		t.Fatalf("relative path under content root should pass allowlist, got: %s", w.Body.String())
	}

	if bytes.Contains(w.Body.Bytes(), []byte("file does not exist")) {
		t.Fatalf("relative path should resolve to existing file, got: %s", w.Body.String())
	}
}

func TestHandleCreate_DefaultAllowedPathsAcceptInsideRejectOutside(t *testing.T) { //nolint:paralleltest // uses t.Chdir
	t.Chdir(t.TempDir())

	contentDir := ".ocm/files"

	allowed, err := resolveDefaultAllowedPaths(contentDir)
	if err != nil {
		t.Fatalf("resolveDefaultAllowedPaths: %v", err)
	}

	contentRoot := allowed[0]
	if err := os.MkdirAll(contentRoot, 0700); err != nil {
		t.Fatalf("MkdirAll content root: %v", err)
	}

	insidePath := filepath.Join(contentRoot, "inside.txt")
	if err := os.WriteFile(insidePath, []byte("inside"), 0600); err != nil {
		t.Fatalf("write inside file: %v", err)
	}

	user := testUser()
	handler := newTestHandler(t, testCurrentUser(user))
	handler.SetAllowedPaths(allowed)

	outsideBody := outgoingCreateBody("example.com", "/etc/passwd")
	outsideReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outsideBody))
	outsideReq.Header.Set("Content-Type", "application/json")

	outsideRec := httptest.NewRecorder()
	handler.HandleCreate(outsideRec, outsideReq)

	if outsideRec.Code != http.StatusBadRequest {
		t.Fatalf("outside path: expected 400, got %d: %s", outsideRec.Code, outsideRec.Body.String())
	}

	if !bytes.Contains(outsideRec.Body.Bytes(), []byte("path not in allowed directories")) {
		t.Fatalf("outside path: expected allowlist error, got: %s", outsideRec.Body.String())
	}

	insideBody := outgoingCreateBody("example.com", insidePath)
	insideReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(insideBody))
	insideReq.Header.Set("Content-Type", "application/json")

	insideRec := httptest.NewRecorder()
	handler.HandleCreate(insideRec, insideReq)

	if insideRec.Code == http.StatusBadRequest &&
		bytes.Contains(insideRec.Body.Bytes(), []byte("path not in allowed directories")) {
		t.Fatalf("inside path should pass allowlist, got: %s", insideRec.Body.String())
	}
}

func testUser() *identity.User {
	return &identity.User{ID: "user-uuid", Username: "alice"}
}
