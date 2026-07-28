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

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
)

func TestHandleVerifyAccess_BearerSuccess(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, "prov-va-ok", "sender.example.com", "hello.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	fileContent := "E2E test file content"
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
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
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

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
	share := createAcceptedShareForUser(repo, "prov-va-fail", "sender.example.com", "missing.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
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
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if resp.OK {
		t.Error("expected ok=false")
	}

	if resp.ReasonCode != "discovery_failed" {
		t.Errorf("expected reasonCode discovery_failed, got %s", resp.ReasonCode)
	}
}

func TestHandleVerifyAccess_SignatureFailureMapsToPolicyDenied(t *testing.T) { //nolint:dupl // intentional: parallel verify-access tests share HTTP setup but assert different reason codes
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, "prov-va-signature", "sender.example.com", "missing.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
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
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if resp.ReasonCode != "policy_denied" {
		t.Errorf("expected reasonCode policy_denied, got %s", resp.ReasonCode)
	}
}

func TestHandleVerifyAccess_ReasonErrorDiscoveryDisabledIsPreserved(t *testing.T) { //nolint:dupl // intentional: parallel verify-access tests share HTTP setup but assert different reason codes
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, "prov-va-disabled", "sender.example.com", "missing.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
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
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if resp.ReasonCode != "discovery_disabled" {
		t.Errorf("expected reasonCode discovery_disabled, got %s", resp.ReasonCode)
	}
}

func TestHandleVerifyAccess_BoundedPreviewTruncation(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, "prov-va-big", "sender.example.com", "big.bin")

	userA := &identity.User{ID: userAID, Username: "alice"}
	bigBody := strings.Repeat("x", 5000)
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
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
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

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
	share := createAcceptedShareForUser(repo, "prov-va-remote-err", "sender.example.com", "forbidden.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
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
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if resp.OK {
		t.Error("expected ok=false")
	}

	if resp.ReasonCode != "unreachable" {
		t.Errorf("expected reasonCode unreachable, got %s", resp.ReasonCode)
	}

	if !strings.Contains(resp.Error, "403") {
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
