// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func TestAcceptInviteRedirectRoundTrip(t *testing.T) {
	ts := harness.StartTestServerWithConfig(t, func(cfg *config.Config) {
		ensureServiceConfig(cfg, "ui", map[string]any{
			"wayf":          map[string]any{"enabled": true},
			"invite_accept": map[string]any{"enabled": true},
		})
	})

	client := noRedirectClient()

	token := "test-invite-token"
	providerDomain := "alice.example.com"
	acceptPath := "/ui/accept-invite?token=" + url.QueryEscape(token) +
		"&providerDomain=" + url.QueryEscape(providerDomain)

	loginURL := getAcceptInviteLoginRedirect(t, client, ts.BaseURL, acceptPath)
	assertLoginPageServesSafeRedirect(t, client, ts.BaseURL, loginURL, acceptPath)
}

// noRedirectClient returns an HTTP client that does not follow redirects.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// getAcceptInviteLoginRedirect requests the accept-invite page unauthenticated
// and returns the parsed login redirect URL.
func getAcceptInviteLoginRedirect(t *testing.T, client *http.Client, baseURL, acceptPath string) *url.URL {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+acceptPath, nil)
	if err != nil {
		t.Fatalf("build accept-invite request: %v", err)
	}

	resp, err := client.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("GET accept-invite: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if _, derr := io.Copy(io.Discard, resp.Body); derr != nil {
		t.Errorf("drain response body: %v", derr)
	}

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 for unauthenticated accept-invite, got %d", resp.StatusCode)
	}

	loginLocation := resp.Header.Get("Location")
	if loginLocation == "" {
		t.Fatal("expected Location header on accept-invite redirect")
	}

	loginURL, err := url.Parse(loginLocation)
	if err != nil {
		t.Fatalf("parse login Location: %v", err)
	}

	if !strings.HasSuffix(loginURL.Path, "/ui/login") {
		t.Fatalf("expected redirect to login, got path %q", loginURL.Path)
	}

	if returnURL := loginURL.Query().Get("redirect"); returnURL != acceptPath {
		t.Fatalf("login redirect param = %q, want %q", returnURL, acceptPath)
	}

	return loginURL
}

// assertLoginPageServesSafeRedirect requests the login page and checks it
// carries the safe redirect handling.
func assertLoginPageServesSafeRedirect(t *testing.T, client *http.Client, baseURL string, loginURL *url.URL, acceptPath string) {
	t.Helper()

	loginReq, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		baseURL+loginURL.Path+"?"+loginURL.RawQuery,
		nil,
	)
	if err != nil {
		t.Fatalf("build login request: %v", err)
	}

	loginResp, err := client.Do(loginReq) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("GET login: %v", err)
	}
	defer tshttp.MustClose(t, loginResp.Body)

	loginBody, err := io.ReadAll(loginResp.Body)
	if err != nil {
		t.Fatalf("read login body: %v", err)
	}

	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from login page, got %d", loginResp.StatusCode)
	}

	if loginURL.Query().Get("redirect") != acceptPath {
		t.Fatalf("login request missing redirect query, got %q", loginURL.Query().Get("redirect"))
	}

	body := string(loginBody)
	if !strings.Contains(body, "getSafeRedirect") {
		t.Error("expected login page to include safe redirect handling")
	}
}

func TestAcceptInviteRedirectRoundTrip_WithExternalBasePath(t *testing.T) {
	ts := harness.StartTestServerWithConfig(t, func(cfg *config.Config) {
		cfg.ExternalBasePath = "/ocm"
		ensureServiceConfig(cfg, "ui", map[string]any{
			"wayf":          map[string]any{"enabled": true},
			"invite_accept": map[string]any{"enabled": true},
		})
	})

	client := noRedirectClient()

	token := "basepath-token"
	providerDomain := "sender.example.com"
	acceptPath := "/ocm/ui/accept-invite?token=" + url.QueryEscape(token) +
		"&providerDomain=" + url.QueryEscape(providerDomain)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.BaseURL+acceptPath, nil)
	if err != nil {
		t.Fatalf("build accept-invite request: %v", err)
	}

	resp, err := client.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("GET accept-invite: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if _, derr := io.Copy(io.Discard, resp.Body); derr != nil {
		t.Errorf("drain response body: %v", derr)
	}

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	loginURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}

	if loginURL.Path != "/ocm/ui/login" {
		t.Fatalf("expected /ocm/ui/login, got %q", loginURL.Path)
	}

	returnURL := loginURL.Query().Get("redirect")
	if returnURL != acceptPath {
		t.Fatalf("redirect = %q, want %q", returnURL, acceptPath)
	}
}
