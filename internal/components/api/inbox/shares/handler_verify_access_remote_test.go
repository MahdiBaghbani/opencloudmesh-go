// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
)

func TestHandleVerifyAccess_BearerSuccess(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createAcceptedShareForUser(t, repo, "prov-va-ok", "sender.example.com", "hello.txt")

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
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createAcceptedShareForUser(t, repo, "prov-va-fail", "sender.example.com", "missing.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
		return nil, reason.NewClassifiedError(
			reason.ReasonDiscoveryFailed,
			"failed to discover sender",
			errors.New("connection refused"),
		)
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

	if resp.ReasonCode != "discovery_failed" {
		t.Errorf("expected reasonCode discovery_failed, got %s", resp.ReasonCode)
	}
}

// assertVerifyAccessError wires an accessor that fails with accessErr and
// asserts verify-access returns wantStatus carrying wantReasonCode.
func assertVerifyAccessError(t *testing.T, providerLabel string, accessErr error, wantStatus int, wantReasonCode string) {
	t.Helper()

	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createAcceptedShareForUser(t, repo, providerLabel, "sender.example.com", "missing.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
		return nil, accessErr
	}}
	router := newTestRouterWithAccess(repo, ac, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+share.ShareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != wantStatus {
		t.Fatalf("expected %d, got %d: %s", wantStatus, w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if resp.ReasonCode != wantReasonCode {
		t.Errorf("expected reasonCode %s, got %s", wantReasonCode, resp.ReasonCode)
	}
}

func TestHandleVerifyAccess_SignatureFailureMapsToPolicyDenied(t *testing.T) {
	t.Parallel()
	assertVerifyAccessError(
		t,
		"prov-va-signature",
		reason.NewClassifiedError(reason.ReasonSignatureRequired, "signature required", nil),
		http.StatusForbidden,
		"policy_denied",
	)
}

func TestHandleVerifyAccess_ReasonErrorDiscoveryDisabledIsPreserved(t *testing.T) {
	t.Parallel()
	assertVerifyAccessError(
		t,
		"prov-va-disabled",
		reason.New(reason.PeerDiscoveryDisabled, "discovery disabled", nil),
		http.StatusNotImplemented,
		"discovery_disabled",
	)
}

func TestHandleVerifyAccess_BoundedPreviewTruncation(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createAcceptedShareForUser(t, repo, "prov-va-big", "sender.example.com", "big.bin")

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
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createAcceptedShareForUser(t, repo, "prov-va-remote-err", "sender.example.com", "forbidden.txt")

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

	if !strings.Contains(resp.Error, "403") {
		t.Errorf("expected error to mention status code, got %q", resp.Error)
	}
}

func TestHandleVerifyAccess_Unauthenticated(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	router := newTestRouterWithAccess(repo, nil, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/some-id/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
