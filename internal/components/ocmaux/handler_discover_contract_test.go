// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ocmaux_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocmaux"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestHandleDiscover_MissingBase(t *testing.T) {
	t.Parallel()

	h := ocmaux.NewAuxHandler(nil, nil, testLogger())

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/discover", nil)
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if resp["success"] != false {
		t.Error("expected success=false")
	}
}

func TestHandleDiscover_NoDiscoveryClient(t *testing.T) {
	t.Parallel()

	h := ocmaux.NewAuxHandler(nil, nil, testLogger())

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/discover?base=https://example.com", nil)
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", w.Code)
	}

	var resp struct {
		ReasonCode string `json:"reasonCode"`
	}

	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if resp.ReasonCode != reason.PeerDiscoveryDisabled {
		t.Errorf("expected reasonCode %q, got %q", reason.PeerDiscoveryDisabled, resp.ReasonCode)
	}
}

func TestHandleDiscover_Success(t *testing.T) {
	t.Parallel()

	var serverURL string

	discServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			mustEncodeJSON(t, w, map[string]any{
				"enabled":            true,
				"apiVersion":         "1.4.0",
				"endPoint":           serverURL + "/ocm",
				"provider":           "TestProvider",
				"inviteAcceptDialog": "/apps/ocm/invite-accept",
				"resourceTypes":      []any{},
				"criteria":           []any{},
			})

			return
		}

		http.NotFound(w, r)
	}))
	defer discServer.Close()

	serverURL = discServer.URL

	httpCfg := tshttp.PermissiveConfig()
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

	h := ocmaux.NewAuxHandler(nil, discClient, testLogger())

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/discover?base="+discServer.URL, nil)
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Success   bool `json:"success"`
		Discovery *struct {
			Enabled  bool   `json:"enabled"`
			Provider string `json:"provider"`
		} `json:"discovery"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if !resp.Success {
		t.Error("expected success=true")
	}

	if resp.Discovery == nil {
		t.Fatal("expected discovery object")
	}

	if resp.Discovery.Provider != "TestProvider" {
		t.Errorf("expected provider 'TestProvider', got %q", resp.Discovery.Provider)
	}
}

func TestHandleDiscover_InviteAcceptDialogAbsolute(t *testing.T) {
	t.Parallel()

	var serverURL string

	discServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			mustEncodeJSON(t, w, map[string]any{
				"enabled":            true,
				"apiVersion":         "1.4.0",
				"endPoint":           serverURL + "/ocm",
				"inviteAcceptDialog": "/apps/ocm/invite-accept",
				"resourceTypes":      []any{},
				"criteria":           []any{},
			})

			return
		}

		http.NotFound(w, r)
	}))
	defer discServer.Close()

	serverURL = discServer.URL

	httpCfg := tshttp.PermissiveConfig()
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
	h := ocmaux.NewAuxHandler(nil, discClient, testLogger())

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/discover?base="+discServer.URL, nil)
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Success                    bool   `json:"success"`
		InviteAcceptDialogAbsolute string `json:"inviteAcceptDialogAbsolute"`
		Discovery                  *struct {
			InviteAcceptDialog string `json:"inviteAcceptDialog"`
		} `json:"discovery"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if !resp.Success {
		t.Error("expected success=true")
	}

	if resp.InviteAcceptDialogAbsolute == "" {
		t.Error("expected non-empty inviteAcceptDialogAbsolute")
	}

	if resp.InviteAcceptDialogAbsolute == "/apps/ocm/invite-accept" {
		t.Error("expected absolute URL, got relative")
	}
}

func TestHandleDiscover_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	h := ocmaux.NewAuxHandler(nil, nil, testLogger())

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/discover?base=https://example.com", nil)
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleDiscover_DiscoveryFailureReasonCode(t *testing.T) {
	t.Parallel()

	discServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer discServer.Close()

	httpCfg := tshttp.PermissiveConfig()
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
	h := ocmaux.NewAuxHandler(nil, discClient, testLogger())

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/discover?base="+discServer.URL, nil)
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Success    bool   `json:"success"`
		ReasonCode string `json:"reasonCode"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if resp.Success {
		t.Fatal("expected success=false")
	}

	if resp.ReasonCode != reason.PeerDiscoveryFailed {
		t.Fatalf("expected reasonCode %q, got %q", reason.PeerDiscoveryFailed, resp.ReasonCode)
	}
}
