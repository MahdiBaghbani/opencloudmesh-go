package shares_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
)

func TestHandleVerifyAccess_RedactsSecretsFromPreview(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, userAID, "prov-va-redact", "sender.example.com", "redact.txt")
	secret := share.SharedSecret

	userA := &identity.User{ID: userAID, Username: "alice"}
	leakyBody := "redirect?code=" + secret + "&sharedSecret=" + secret + "&other=safe"
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(bytes.NewBufferString(leakyBody)),
			},
		}, nil
	}}
	router := newTestRouterWithAccess(repo, ac, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if containsStr(body, secret) {
		t.Errorf("response body must not contain the shared secret, got %q", body)
	}
	if containsStr(body, "code=") {
		t.Errorf("response body must not contain 'code=', got %q", body)
	}
	if containsStr(body, "sharedSecret") {
		t.Errorf("response body must not contain 'sharedSecret', got %q", body)
	}
}

func TestHandleVerifyAccess_RedactsPeerContentType(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, userAID, "prov-va-redact-ct", "sender.example.com", "ct.txt")
	secret := share.SharedSecret

	userA := &identity.User{ID: userAID, Username: "alice"}
	leakyContentType := "application/x-custom; code=" + secret + "; sharedSecret=" + secret + "; token=" + secret
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{leakyContentType}},
				Body:       io.NopCloser(bytes.NewBufferString("ok")),
			},
		}, nil
	}}
	router := newTestRouterWithAccess(repo, ac, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if !resp.OK {
		t.Fatal("expected ok=true")
	}
	if containsStr(resp.ContentType, secret) {
		t.Errorf("contentType must not contain the shared secret, got %q", resp.ContentType)
	}
	if containsStr(resp.ContentType, "code=") {
		t.Errorf("contentType must not contain 'code=', got %q", resp.ContentType)
	}
	if containsStr(resp.ContentType, "sharedSecret") {
		t.Errorf("contentType must not contain 'sharedSecret', got %q", resp.ContentType)
	}
}

func TestHandleVerifyAccess_RedactsPeerStatusOnNon2xx(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, userAID, "prov-va-redact-status", "sender.example.com", "err.txt")
	secret := share.SharedSecret

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
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

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.OK {
		t.Error("expected ok=false")
	}
	if resp.ReasonCode != "unreachable" {
		t.Errorf("expected reasonCode unreachable, got %s", resp.ReasonCode)
	}
	if containsStr(resp.Error, secret) {
		t.Errorf("error must not contain the shared secret, got %q", resp.Error)
	}
	if !containsStr(resp.Error, "403") {
		t.Errorf("expected error to mention status code, got %q", resp.Error)
	}
}

func TestHandleVerifyAccess_RedactsCodeAndSharedSecretEvenWithEmptySecret(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := &sharesinbox.IncomingShare{
		ProviderID:      "prov-va-empty-secret",
		SenderHost:      "sender.example.com",
		ShareWith:       userAID + "@example.com",
		RecipientUserID: userAID,
		Status:          sharesinbox.ShareStatusAccepted,
		ResourceType:    "file",
		Name:            "empty-secret.txt",
		Owner:           "owner@sender.example.com",
		Sender:          "sender@sender.example.com",
		ShareType:       "user",
		Permissions:     []string{"read"},
		WebDAVID:        "webdav-id-empty",
		SharedSecret:    "",
	}
	repo.Create(context.Background(), share)

	userA := &identity.User{ID: userAID, Username: "alice"}
	leakyBody := "redirect?code=abc&sharedSecret=xyz"
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(bytes.NewBufferString(leakyBody)),
			},
		}, nil
	}}
	router := newTestRouterWithAccess(repo, ac, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if containsStr(body, "code=") {
		t.Errorf("response body must not contain 'code=', got %q", body)
	}
	if containsStr(body, "sharedSecret") {
		t.Errorf("response body must not contain 'sharedSecret', got %q", body)
	}
}
