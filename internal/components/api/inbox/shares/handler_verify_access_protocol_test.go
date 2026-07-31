// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
)

// runVerifyAccess posts to /verify-access through a mock accessor that answers
// 200 with the given content type, capturing the protocol and share info the
// handler passed to the access client.
func runVerifyAccess(t *testing.T, repo *sharesincoming.MemoryIncomingShareRepo, user *identity.User, shareID, contentType, body string) (string, *access.ShareInfo) {
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
	repo := sharesincoming.NewMemoryIncomingShareRepo()
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

func TestHandleVerifyAccess_SelectsWebappProtocolAndPopulatesShareInfo(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createAcceptedWebappShareForUser(t, repo, userAID, "prov-va-webapp", "sender.example.com", "webapp-file.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}

	gotProtocol, gotShareInfo := runVerifyAccess(t, repo, userA, share.ShareID, "text/html", "<html></html>")

	if gotProtocol != access.ProtocolWebapp {
		t.Errorf("expected protocol %q, got %q", access.ProtocolWebapp, gotProtocol)
	}

	assertWebappShareInfo(t, gotShareInfo, share)
}

// assertWebappShareInfo checks the ShareInfo handed to the access client for a
// webapp share, including both webapp arm fields and the WebDAV credentials.
func assertWebappShareInfo(t *testing.T, got *access.ShareInfo, share *sharesincoming.IncomingShare) {
	t.Helper()

	if got == nil {
		t.Fatal("expected ShareInfo to be passed to access client")
	}

	if got.ProtocolName != share.ProtocolName {
		t.Errorf("expected ProtocolName %q, got %q", share.ProtocolName, got.ProtocolName)
	}

	if got.WebappURI != share.WebappURI {
		t.Errorf("expected WebappURI %q, got %q", share.WebappURI, got.WebappURI)
	}

	if !slices.Equal(got.WebappTargets, share.WebappTargets) {
		t.Errorf("expected WebappTargets %v, got %v", share.WebappTargets, got.WebappTargets)
	}

	if !slices.Equal(got.WebappPermissions, share.WebappPermissions) {
		t.Errorf("expected WebappPermissions %v, got %v", share.WebappPermissions, got.WebappPermissions)
	}

	if got.WebDAVID != share.WebDAVID {
		t.Errorf("expected WebDAVID %q, got %q", share.WebDAVID, got.WebDAVID)
	}

	if got.SharedSecret != share.SharedSecret {
		t.Errorf("expected SharedSecret to be passed to access client")
	}

	if !slices.Equal(got.Requirements, share.Requirements) {
		t.Errorf("expected Requirements %v, got %v", share.Requirements, got.Requirements)
	}
}

func TestHandleVerifyAccess_SelectsWebappProtocolByWebappURI(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createAcceptedWebappShareForUser(t, repo, userAID, "prov-va-webapp-uri", "sender.example.com", "uri-only.txt")
	share.ProtocolName = "webdav"

	userA := &identity.User{ID: userAID, Username: "alice"}

	gotProtocol, gotShareInfo := runVerifyAccess(t, repo, userA, share.ShareID, "text/html", "<html></html>")

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
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createAcceptedWebappShareForUser(t, repo, userAID, "prov-va-webapp-name", "sender.example.com", "name-only.txt")
	share.WebappURI = ""

	userA := &identity.User{ID: userAID, Username: "alice"}

	gotProtocol, gotShareInfo := runVerifyAccess(t, repo, userA, share.ShareID, "text/html", "<html></html>")

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
