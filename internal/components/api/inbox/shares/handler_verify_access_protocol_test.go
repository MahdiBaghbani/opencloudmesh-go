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
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
)

// runVerifyAccess posts to /verify-access through a mock accessor that answers
// 200 with the given content type, capturing the protocol and share info the
// handler passed to the access client.
func runVerifyAccess(t *testing.T, repo sharesincoming.IncomingShareRepo, user *identity.User, shareID, contentType, body string) (string, *access.ShareInfo) {
	t.Helper()

	var (
		gotProtocol  string
		gotShareInfo *access.ShareInfo
	)

	ac := &mockAccessor{accessFn: func(_ context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		gotProtocol = opts.Protocol
		gotShareInfo = opts.Share

		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{contentType}},
				Body:       io.NopCloser(bytes.NewBufferString(body)),
			},
		}, nil
	}}
	router := newTestRouterWithAccess(repo, ac, user)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+shareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	return gotProtocol, gotShareInfo
}

func TestHandleVerifyAccess_DefaultsToWebDAVProtocol(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createAcceptedShareForUser(t, repo, "prov-va-webdav", "sender.example.com", "file.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}

	gotProtocol, gotShareInfo := runVerifyAccess(t, repo, userA, share.ShareID, "text/plain", "ok")

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

func TestHandleVerifyAccess_PassesEmptySubPath(t *testing.T) {
	t.Parallel()

	var gotSubPath string

	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createAcceptedShareForUser(t, repo, "prov-va-subpath", "sender.example.com", "file.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}

	ac := &mockAccessor{accessFn: func(_ context.Context, opts access.AccessOptions) (*access.AccessResult, error) {
		gotSubPath = opts.SubPath

		return &access.AccessResult{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
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

	if gotSubPath != "" {
		t.Errorf("expected empty SubPath, got %q", gotSubPath)
	}
}

// assertVerifyAccessUnsupportedProtocol posts verify-access and expects HTTP 501
// with reasonCode unsupported_protocol without calling the access client.
func assertVerifyAccessUnsupportedProtocol(t *testing.T, repo sharesincoming.IncomingShareRepo, shareID string) {
	t.Helper()

	userA := &identity.User{ID: userAID, Username: "alice"}
	ac := &mockAccessor{accessFn: func(_ context.Context, _ access.AccessOptions) (*access.AccessResult, error) {
		t.Fatal("access client should not be called for unsupported webapp protocol")

		return nil, nil //nolint:nilnil // test: unreachable after t.Fatal; satisfies the mock accessor signature
	}}
	router := newTestRouterWithAccess(repo, ac, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+shareID+"/verify-access", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", w.Code, w.Body.String())
	}

	var resp inboxshares.VerifyAccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if resp.ReasonCode != "unsupported_protocol" {
		t.Errorf("expected reasonCode unsupported_protocol, got %s", resp.ReasonCode)
	}
}

func TestHandleVerifyAccess_RejectsWebappShare(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createAcceptedWebappShareForUser(t, repo, userAID, "prov-va-webapp", "sender.example.com", "webapp-file.txt")

	assertVerifyAccessUnsupportedProtocol(t, repo, share.ShareID)
}

func TestHandleVerifyAccess_RejectsWebappByWebappURI(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares

	share := &sharesincoming.IncomingShare{
		ProviderID:        "prov-va-webapp-uri",
		SenderHost:        "sender.example.com",
		ShareWith:         userAID + "@example.com",
		RecipientUserID:   userAID,
		Status:            shares.ShareStatusAccepted,
		ResourceType:      "file",
		Name:              "uri-only.txt",
		Owner:             "owner@sender.example.com",
		Sender:            "sender@sender.example.com",
		ShareType:         "user",
		Permissions:       []string{"read"},
		WebDAVID:          "webdav-id-prov-va-webapp-uri",
		SharedSecret:      "secret-prov-va-webapp-uri",
		Requirements:      []string{"must-exchange-token"},
		ProtocolName:      "webdav",
		WebappURI:         "https://app.sender.example.com/launch?share=prov-va-webapp-uri",
		WebappTargets:     []string{"blank", "_self"},
		WebappPermissions: []string{"view", "share"},
	}
	if err := repo.Create(context.Background(), share); err != nil {
		t.Fatal(err)
	}

	assertVerifyAccessUnsupportedProtocol(t, repo, share.ShareID)
}

func TestHandleVerifyAccess_RejectsWebappByProtocolName(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares

	share := &sharesincoming.IncomingShare{
		ProviderID:        "prov-va-webapp-name",
		SenderHost:        "sender.example.com",
		ShareWith:         userAID + "@example.com",
		RecipientUserID:   userAID,
		Status:            shares.ShareStatusAccepted,
		ResourceType:      "file",
		Name:              "name-only.txt",
		Owner:             "owner@sender.example.com",
		Sender:            "sender@sender.example.com",
		ShareType:         "user",
		Permissions:       []string{"read"},
		WebDAVID:          "webdav-id-prov-va-webapp-name",
		SharedSecret:      "secret-prov-va-webapp-name",
		Requirements:      []string{"must-exchange-token"},
		ProtocolName:      "webapp",
		WebappTargets:     []string{"blank", "_self"},
		WebappPermissions: []string{"view", "share"},
	}
	if err := repo.Create(context.Background(), share); err != nil {
		t.Fatal(err)
	}

	assertVerifyAccessUnsupportedProtocol(t, repo, share.ShareID)
}
