// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
)

func TestHandleVerifyAccess_RedactsSecretsFromPreview(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createAcceptedShareForUser(t, repo, "prov-va-redact", "sender.example.com", "redact.txt")
	secret := share.SharedSecret

	userA := &identity.User{ID: userAID, Username: "alice"}
	leakyBody := "redirect?code=" + secret + "&sharedSecret=" + secret + "&other=safe"
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(bytes.NewBufferString(leakyBody)),
			},
		}, nil
	}}
	router := newTestRouterWithAccess(repo, ac, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if strings.Contains(body, secret) {
		t.Errorf("response body must not contain the shared secret, got %q", body)
	}

	if strings.Contains(body, "code=") {
		t.Errorf("response body must not contain 'code=', got %q", body)
	}

	if strings.Contains(body, "sharedSecret") {
		t.Errorf("response body must not contain 'sharedSecret', got %q", body)
	}
}

func TestHandleVerifyAccess_RedactsPeerContentType(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createAcceptedShareForUser(t, repo, "prov-va-redact-ct", "sender.example.com", "ct.txt")
	secret := share.SharedSecret

	userA := &identity.User{ID: userAID, Username: "alice"}
	leakyContentType := "application/x-custom; code=" + secret + "; sharedSecret=" + secret + "; token=" + secret
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{leakyContentType}},
				Body:       io.NopCloser(bytes.NewBufferString("ok")),
			},
		}, nil
	}}
	router := newTestRouterWithAccess(repo, ac, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !resp.OK {
		t.Fatal("expected ok=true")
	}

	if strings.Contains(resp.ContentType, secret) {
		t.Errorf("contentType must not contain the shared secret, got %q", resp.ContentType)
	}

	if strings.Contains(resp.ContentType, "code=") {
		t.Errorf("contentType must not contain 'code=', got %q", resp.ContentType)
	}

	if strings.Contains(resp.ContentType, "sharedSecret") {
		t.Errorf("contentType must not contain 'sharedSecret', got %q", resp.ContentType)
	}
}

func TestHandleVerifyAccess_RedactsPeerStatusOnNon2xx(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createAcceptedShareForUser(t, repo, "prov-va-redact-status", "sender.example.com", "err.txt")
	secret := share.SharedSecret

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusForbidden,
				Status:     "403 Forbidden token=" + secret,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(bytes.NewBufferString("denied")),
			},
		}, nil
	}}
	router := newTestRouterWithAccess(repo, ac, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if resp.OK {
		t.Error("expected ok=false")
	}

	if resp.ReasonCode != "unreachable" {
		t.Errorf("expected reasonCode unreachable, got %s", resp.ReasonCode)
	}

	if strings.Contains(resp.Error, secret) {
		t.Errorf("error must not contain the shared secret, got %q", resp.Error)
	}

	if !strings.Contains(resp.Error, "403") {
		t.Errorf("expected error to mention status code, got %q", resp.Error)
	}
}

func TestHandleVerifyAccess_RedactsCodeAndSharedSecretEvenWithEmptySecret(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingShares

	share := &sharesincoming.IncomingShare{
		ProviderID:      "prov-va-empty-secret",
		SenderHost:      "sender.example.com",
		ShareWith:       userAID + "@example.com",
		RecipientUserID: userAID,
		Status:          shares.ShareStatusAccepted,
		ResourceType:    "file",
		Name:            "empty-secret.txt",
		Owner:           "owner@sender.example.com",
		Sender:          "sender@sender.example.com",
		ShareType:       "user",
		Permissions:     []string{"read"},
		WebDAVID:        "webdav-id-empty",
		SharedSecret:    "",
	}
	if err := repo.Create(context.Background(), share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	userA := &identity.User{ID: userAID, Username: "alice"}
	leakyBody := "redirect?code=abc&sharedSecret=xyz"
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(bytes.NewBufferString(leakyBody)),
			},
		}, nil
	}}
	router := newTestRouterWithAccess(repo, ac, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if strings.Contains(body, "code=") {
		t.Errorf("response body must not contain 'code=', got %q", body)
	}

	if strings.Contains(body, "sharedSecret") {
		t.Errorf("response body must not contain 'sharedSecret', got %q", body)
	}
}
