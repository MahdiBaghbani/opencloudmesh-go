package shares_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
)

type mockAccessor struct {
	accessFn func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error)
}

func (m *mockAccessor) Access(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
	return m.accessFn(ctx, opts)
}

func newTestRouterWithAccess(
	repo sharesinbox.IncomingShareRepo,
	sender sharesinbox.NotificationSender,
	ac access.RemoteAccessor,
	user *identity.User,
) http.Handler {
	h := inboxshares.NewHandler(repo, sender, ac, currentUserFunc(user), testLogger)
	r := chi.NewRouter()
	r.Route("/inbox/shares", func(r chi.Router) {
		r.Get("/", h.HandleList)
		r.Get("/{shareId}", h.HandleGetDetail)
		r.Post("/{shareId}/accept", h.HandleAccept)
		r.Post("/{shareId}/decline", h.HandleDecline)
		r.Post("/{shareId}/verify-access", h.HandleVerifyAccess)
	})
	return r
}

func createAcceptedShareForUser(
	repo *sharesinbox.MemoryIncomingShareRepo,
	recipientUserID, providerID, senderHost, name string,
) *sharesinbox.IncomingShare {
	share := &sharesinbox.IncomingShare{
		ProviderID:      providerID,
		SenderHost:      senderHost,
		ShareWith:       recipientUserID + "@example.com",
		RecipientUserID: recipientUserID,
		Status:          sharesinbox.ShareStatusAccepted,
		ResourceType:    "file",
		Name:            name,
		Owner:           "owner@sender.example.com",
		Sender:          "sender@sender.example.com",
		ShareType:       "user",
		Permissions:     []string{"read"},
		WebDAVID:        "webdav-id-" + providerID,
		SharedSecret:    "secret-" + providerID,
	}
	repo.Create(context.Background(), share)
	return share
}

func TestHandleVerifyAccess_CrossUserReturns404(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, userAID, "prov-va-cross", "sender.example.com", "file.txt")

	userB := &identity.User{ID: userBID, Username: "bob"}
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		t.Fatal("access client should not be called for cross-user request")
		return nil, nil
	}}
	router := newTestRouterWithAccess(repo, nil, ac, userB)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user verify, got %d", w.Code)
	}
}

func TestHandleVerifyAccess_ShareNotAcceptedReturns400(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createShareForUser(repo, userAID, "prov-va-pending", "sender.example.com")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		t.Fatal("access client should not be called for non-accepted share")
		return nil, nil
	}}
	router := newTestRouterWithAccess(repo, nil, ac, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.ReasonCode != "share_not_accepted" {
		t.Errorf("expected reasonCode share_not_accepted, got %s", resp.ReasonCode)
	}
}

func TestHandleVerifyAccess_UnsafePathReturns400(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, userAID, "prov-va-unsafe", "sender.example.com", "../etc/passwd")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		t.Fatal("access client should not be called for unsafe path")
		return nil, nil
	}}
	router := newTestRouterWithAccess(repo, nil, ac, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.ReasonCode != "unsafe_path" {
		t.Errorf("expected reasonCode unsafe_path, got %s", resp.ReasonCode)
	}
}

func TestHandleVerifyAccess_BearerSuccess(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, userAID, "prov-va-ok", "sender.example.com", "hello.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	fileContent := "E2E test file content"
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(bytes.NewBufferString(fileContent)),
			},
			TokenExchanged: false,
			MethodUsed:     "bearer",
		}, nil
	}}
	router := newTestRouterWithAccess(repo, nil, ac, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if !resp.OK {
		t.Error("expected ok=true")
	}
	if resp.MethodUsed != "bearer" {
		t.Errorf("expected methodUsed bearer, got %s", resp.MethodUsed)
	}
	if resp.HTTPStatus != 200 {
		t.Errorf("expected httpStatus 200, got %d", resp.HTTPStatus)
	}
	if resp.ContentType != "text/plain" {
		t.Errorf("expected contentType text/plain, got %s", resp.ContentType)
	}
	if resp.ContentPreview != fileContent {
		t.Errorf("expected contentPreview %q, got %q", fileContent, resp.ContentPreview)
	}
	if resp.ContentPreviewTruncated {
		t.Error("expected contentPreviewTruncated=false for small body")
	}
}

func TestHandleVerifyAccess_RemoteFailureReturnsReasonCode(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, userAID, "prov-va-fail", "sender.example.com", "missing.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		return nil, peercompat.NewClassifiedError(
			peercompat.ReasonDiscoveryFailed,
			"failed to discover sender",
			fmt.Errorf("connection refused"),
		)
	}}
	router := newTestRouterWithAccess(repo, nil, ac, userA)

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
	if resp.ReasonCode != "discovery_failed" {
		t.Errorf("expected reasonCode discovery_failed, got %s", resp.ReasonCode)
	}
}

func TestHandleVerifyAccess_SignatureFailureMapsToPolicyDenied(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, userAID, "prov-va-signature", "sender.example.com", "missing.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		return nil, peercompat.NewClassifiedError(
			peercompat.ReasonSignatureRequired,
			"signature required",
			nil,
		)
	}}
	router := newTestRouterWithAccess(repo, nil, ac, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.ReasonCode != "policy_denied" {
		t.Errorf("expected reasonCode policy_denied, got %s", resp.ReasonCode)
	}
}

func TestHandleVerifyAccess_ReasonErrorDiscoveryDisabledIsPreserved(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, userAID, "prov-va-disabled", "sender.example.com", "missing.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		return nil, reason.New(reason.PeerDiscoveryDisabled, "discovery disabled", nil)
	}}
	router := newTestRouterWithAccess(repo, nil, ac, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.ReasonCode != "discovery_disabled" {
		t.Errorf("expected reasonCode discovery_disabled, got %s", resp.ReasonCode)
	}
}

func TestHandleVerifyAccess_BoundedPreviewTruncation(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, userAID, "prov-va-big", "sender.example.com", "big.bin")

	userA := &identity.User{ID: userAID, Username: "alice"}
	bigBody := strings.Repeat("x", 5000)
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/octet-stream"}},
				Body:       io.NopCloser(bytes.NewBufferString(bigBody)),
			},
			MethodUsed: "bearer",
		}, nil
	}}
	router := newTestRouterWithAccess(repo, nil, ac, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if !resp.OK {
		t.Error("expected ok=true")
	}
	if !resp.ContentPreviewTruncated {
		t.Error("expected contentPreviewTruncated=true for large body")
	}
	if len(resp.ContentPreview) != 4096 {
		t.Errorf("expected preview length 4096, got %d", len(resp.ContentPreview))
	}
}

func TestHandleVerifyAccess_RemoteNon2xxReturns502(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, userAID, "prov-va-remote-err", "sender.example.com", "forbidden.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusForbidden,
				Status:     "403 Forbidden",
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(bytes.NewBufferString("access denied")),
			},
			MethodUsed: "bearer",
		}, nil
	}}
	router := newTestRouterWithAccess(repo, nil, ac, userA)

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
	if !containsStr(resp.Error, "403") {
		t.Errorf("expected error to mention status code, got %q", resp.Error)
	}
}

func TestHandleVerifyAccess_Unauthenticated(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	router := newTestRouterWithAccess(repo, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/some-id/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
