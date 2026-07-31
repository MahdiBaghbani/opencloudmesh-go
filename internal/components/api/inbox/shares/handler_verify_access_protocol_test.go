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
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
)

func TestHandleVerifyAccess_DefaultsToWebDAVProtocol(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createAcceptedShareForUser(repo, "prov-va-webdav", "sender.example.com", "file.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}

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
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createAcceptedWebappShareForUser(repo, userAID, "prov-va-webapp", "sender.example.com", "webapp-file.txt")

	userA := &identity.User{ID: userAID, Username: "alice"}

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
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createAcceptedWebappShareForUser(repo, userAID, "prov-va-webapp-uri", "sender.example.com", "uri-only.txt")
	share.ProtocolName = "webdav"

	userA := &identity.User{ID: userAID, Username: "alice"}

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
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createAcceptedWebappShareForUser(repo, userAID, "prov-va-webapp-name", "sender.example.com", "name-only.txt")
	share.WebappURI = ""

	userA := &identity.User{ID: userAID, Username: "alice"}

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
