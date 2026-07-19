// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func TestAcceptInviteRedirectRoundTrip(t *testing.T) {
	ts := harness.StartTestServerWithConfig(t, func(cfg *config.Config) {
		ensureServiceConfig(cfg, "ui", map[string]any{
			"wayf":          map[string]any{"enabled": true},
			"invite_accept": map[string]any{"enabled": true},
		})
	})

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	token := "test-invite-token"
	providerDomain := "alice.example.com"
	acceptPath := "/ui/accept-invite?token=" + url.QueryEscape(token) +
		"&providerDomain=" + url.QueryEscape(providerDomain)

	resp, err := client.Get(ts.BaseURL + acceptPath)
	if err != nil {
		t.Fatalf("GET accept-invite: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

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

	returnURL := loginURL.Query().Get("redirect")
	if returnURL != acceptPath {
		t.Fatalf("login redirect param = %q, want %q", returnURL, acceptPath)
	}

	loginResp, err := client.Get(ts.BaseURL + loginURL.Path + "?" + loginURL.RawQuery)
	if err != nil {
		t.Fatalf("GET login: %v", err)
	}
	defer loginResp.Body.Close()
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

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	token := "basepath-token"
	providerDomain := "sender.example.com"
	acceptPath := "/ocm/ui/accept-invite?token=" + url.QueryEscape(token) +
		"&providerDomain=" + url.QueryEscape(providerDomain)

	resp, err := client.Get(ts.BaseURL + acceptPath)
	if err != nil {
		t.Fatalf("GET accept-invite: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

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
