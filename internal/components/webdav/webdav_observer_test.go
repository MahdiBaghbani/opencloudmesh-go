// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package webdav

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
)

func authorizedGetRequest(t *testing.T) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	return req
}

func TestServeHTTP_ShareAccessObserverInvokedOnGet(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()
	share := seedShare(t, repo)

	dir := t.TempDir()

	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	share.LocalPath = filePath
	if err := repo.Update(context.Background(), share); err != nil {
		t.Fatal(err)
	}

	if err := tokenStore.Store(context.Background(), unexpiredTestToken("valid-token", share.ShareID)); err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(repo, tokenStore, nil)

	var observed *sharesoutgoing.OutgoingShare

	handler.SetShareAccessObserver(func(_ context.Context, s *sharesoutgoing.OutgoingShare) error {
		observed = s

		return nil
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, authorizedGetRequest(t))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if observed == nil || observed.ShareID != share.ShareID {
		t.Fatalf("observer share = %v, want the served share %s", observed, share.ShareID)
	}
}

func TestServeHTTP_ShareAccessObserverSkippedOnHead(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()
	share := seedShare(t, repo)

	dir := t.TempDir()

	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	share.LocalPath = filePath
	if err := repo.Update(context.Background(), share); err != nil {
		t.Fatal(err)
	}

	if err := tokenStore.Store(context.Background(), unexpiredTestToken("valid-token", share.ShareID)); err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(repo, tokenStore, nil)

	called := false

	handler.SetShareAccessObserver(func(_ context.Context, _ *sharesoutgoing.OutgoingShare) error {
		called = true

		return nil
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodHead, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if called {
		t.Error("observer must not run on HEAD; only an authorized GET opens the file")
	}
}

func TestServeHTTP_ShareAccessObserverErrorSuppressesServe(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()
	share := seedShare(t, repo)

	dir := t.TempDir()

	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	share.LocalPath = filePath
	if err := repo.Update(context.Background(), share); err != nil {
		t.Fatal(err)
	}

	if err := tokenStore.Store(context.Background(), unexpiredTestToken("valid-token", share.ShareID)); err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(repo, tokenStore, nil)
	handler.SetShareAccessObserver(func(_ context.Context, _ *sharesoutgoing.OutgoingShare) error {
		return errors.New("storage unavailable")
	})

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, authorizedGetRequest(t))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestServeHTTP_ShareAccessObserverNotInvokedOnUnauthorized(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()

	seedShare(t, repo)

	handler := NewHandler(repo, tokenStore, nil)

	called := false

	handler.SetShareAccessObserver(func(_ context.Context, _ *sharesoutgoing.OutgoingShare) error {
		called = true

		return nil
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	if called {
		t.Error("observer must not run when the request never authorized")
	}
}
