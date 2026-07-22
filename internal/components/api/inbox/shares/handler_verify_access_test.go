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
	ac access.RemoteAccessor,
	user *identity.User,
) http.Handler {
	h := inboxshares.NewHandler(repo, ac, currentUserFunc(user), testLogger)
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
	router := newTestRouterWithAccess(repo, ac, userB)

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
	router := newTestRouterWithAccess(repo, ac, userA)

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
	router := newTestRouterWithAccess(repo, ac, userA)

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
			AccessToken: "token",
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
		t.Error("expected ok=true")
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
		return nil, reason.NewClassifiedError(
			reason.ReasonDiscoveryFailed,
			"failed to discover sender",
			fmt.Errorf("connection refused"),
		)
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
	if resp.ReasonCode != "discovery_failed" {
		t.Errorf("expected reasonCode discovery_failed, got %s", resp.ReasonCode)
	}
}

func TestHandleVerifyAccess_SignatureFailureMapsToPolicyDenied(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, userAID, "prov-va-signature", "sender.example.com", "missing.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		return nil, reason.NewClassifiedError(
			reason.ReasonSignatureRequired,
			"signature required",
			nil,
		)
	}}
	router := newTestRouterWithAccess(repo, ac, userA)

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
	router := newTestRouterWithAccess(repo, ac, userA)

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
	if !containsStr(resp.Error, "403") {
		t.Errorf("expected error to mention status code, got %q", resp.Error)
	}
}

func TestHandleVerifyAccess_Unauthenticated(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	router := newTestRouterWithAccess(repo, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/inbox/shares/some-id/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func createAcceptedWebappShareForUser(
	repo *sharesinbox.MemoryIncomingShareRepo,
	recipientUserID, providerID, senderHost, name string,
) *sharesinbox.IncomingShare {
	share := &sharesinbox.IncomingShare{
		ProviderID:        providerID,
		SenderHost:        senderHost,
		ShareWith:         recipientUserID + "@example.com",
		RecipientUserID:   recipientUserID,
		Status:            sharesinbox.ShareStatusAccepted,
		ResourceType:      "file",
		Name:              name,
		Owner:             "owner@sender.example.com",
		Sender:            "sender@sender.example.com",
		ShareType:         "user",
		Permissions:       []string{"read"},
		WebDAVID:          "webdav-id-" + providerID,
		SharedSecret:      "secret-" + providerID,
		Requirements:      []string{"must-exchange-token"},
		ProtocolName:      "webapp",
		WebappURI:         "https://app.sender.example.com/launch?share=" + providerID,
		WebappTargets:     []string{"blank", "_self"},
		WebappPermissions: []string{"view", "share"},
	}
	repo.Create(context.Background(), share)
	return share
}

func TestHandleVerifyAccess_DefaultsToWebDAVProtocol(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, userAID, "prov-va-webdav", "sender.example.com", "file.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	var gotProtocol string
	var gotShareInfo *access.ShareInfo
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		gotProtocol = opts.Protocol
		gotShareInfo = opts.Share
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
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
	if gotProtocol != access.ProtocolWebDAV {
		t.Errorf("expected protocol %q, got %q", access.ProtocolWebDAV, gotProtocol)
	}
	if gotShareInfo == nil {
		t.Fatal("expected ShareInfo to be passed to access client")
	}
	if gotShareInfo.WebDAVID != share.WebDAVID {
		t.Errorf("expected WebDAVID %q, got %q", share.WebDAVID, gotShareInfo.WebDAVID)
	}
	if gotShareInfo.SharedSecret != share.SharedSecret {
		t.Errorf("expected SharedSecret to be passed to access client")
	}
}

func TestHandleVerifyAccess_SelectsWebappProtocolAndPopulatesShareInfo(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedWebappShareForUser(repo, userAID, "prov-va-webapp", "sender.example.com", "webapp-file.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	var gotProtocol string
	var gotShareInfo *access.ShareInfo
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		gotProtocol = opts.Protocol
		gotShareInfo = opts.Share
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html"}},
				Body:       io.NopCloser(bytes.NewBufferString("<html></html>")),
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
	if gotProtocol != access.ProtocolWebapp {
		t.Errorf("expected protocol %q, got %q", access.ProtocolWebapp, gotProtocol)
	}
	if gotShareInfo == nil {
		t.Fatal("expected ShareInfo to be passed to access client")
	}
	if gotShareInfo.ProtocolName != share.ProtocolName {
		t.Errorf("expected ProtocolName %q, got %q", share.ProtocolName, gotShareInfo.ProtocolName)
	}
	if gotShareInfo.WebappURI != share.WebappURI {
		t.Errorf("expected WebappURI %q, got %q", share.WebappURI, gotShareInfo.WebappURI)
	}
	if len(gotShareInfo.WebappTargets) != 2 || gotShareInfo.WebappTargets[0] != "blank" || gotShareInfo.WebappTargets[1] != "_self" {
		t.Errorf("expected WebappTargets [blank _self], got %v", gotShareInfo.WebappTargets)
	}
	if len(gotShareInfo.WebappPermissions) != 2 || gotShareInfo.WebappPermissions[0] != "view" || gotShareInfo.WebappPermissions[1] != "share" {
		t.Errorf("expected WebappPermissions [view share], got %v", gotShareInfo.WebappPermissions)
	}
	if gotShareInfo.WebDAVID != share.WebDAVID {
		t.Errorf("expected WebDAVID %q, got %q", share.WebDAVID, gotShareInfo.WebDAVID)
	}
	if gotShareInfo.SharedSecret != share.SharedSecret {
		t.Errorf("expected SharedSecret to be passed to access client")
	}
	if len(gotShareInfo.Requirements) != 1 || gotShareInfo.Requirements[0] != "must-exchange-token" {
		t.Errorf("expected Requirements [must-exchange-token], got %v", gotShareInfo.Requirements)
	}
}

func TestHandleVerifyAccess_SelectsWebappProtocolByWebappURI(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedWebappShareForUser(repo, userAID, "prov-va-webapp-uri", "sender.example.com", "uri-only.txt")
	share.ProtocolName = "webdav"

	userA := &identity.User{ID: userAID, Username: "alice"}
	var gotProtocol string
	var gotShareInfo *access.ShareInfo
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		gotProtocol = opts.Protocol
		gotShareInfo = opts.Share
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html"}},
				Body:       io.NopCloser(bytes.NewBufferString("<html></html>")),
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
	if gotProtocol != access.ProtocolWebapp {
		t.Errorf("expected protocol %q, got %q", access.ProtocolWebapp, gotProtocol)
	}
	if gotShareInfo == nil {
		t.Fatal("expected ShareInfo to be passed to access client")
	}
	if gotShareInfo.ProtocolName != "webdav" {
		t.Errorf("expected ProtocolName %q, got %q", "webdav", gotShareInfo.ProtocolName)
	}
	if gotShareInfo.WebappURI != share.WebappURI {
		t.Errorf("expected WebappURI %q, got %q", share.WebappURI, gotShareInfo.WebappURI)
	}
}

func TestHandleVerifyAccess_SelectsWebappProtocolByProtocolName(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedWebappShareForUser(repo, userAID, "prov-va-webapp-name", "sender.example.com", "name-only.txt")
	share.WebappURI = ""

	userA := &identity.User{ID: userAID, Username: "alice"}
	var gotProtocol string
	var gotShareInfo *access.ShareInfo
	ac := &mockAccessor{accessFn: func(ctx context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		gotProtocol = opts.Protocol
		gotShareInfo = opts.Share
		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html"}},
				Body:       io.NopCloser(bytes.NewBufferString("<html></html>")),
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
	if gotProtocol != access.ProtocolWebapp {
		t.Errorf("expected protocol %q, got %q", access.ProtocolWebapp, gotProtocol)
	}
	if gotShareInfo == nil {
		t.Fatal("expected ShareInfo to be passed to access client")
	}
	if gotShareInfo.ProtocolName != share.ProtocolName {
		t.Errorf("expected ProtocolName %q, got %q", share.ProtocolName, gotShareInfo.ProtocolName)
	}
	if gotShareInfo.WebappURI != "" {
		t.Errorf("expected empty WebappURI, got %q", gotShareInfo.WebappURI)
	}
}

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
