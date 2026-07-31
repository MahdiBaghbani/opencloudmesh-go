// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"bytes"
	"net/http"
	"strconv"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func TestRateLimitOcmauxDiscover(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	extraConfig := `
[http.interceptors.ratelimit.profiles.discover]
requests_per_window = 1
window_seconds = 60

[http.services.ocmaux.ratelimit]
profile = "discover"
`

	binaryPath := harness.BuildBinary(t)

	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:        "ratelimit-ocmaux",
		Mode:        "dev",
		ExtraConfig: extraConfig,
	})
	defer srv.Stop(t)

	discoverURL := srv.BaseURL + "/ocm-aux/discover?base=" + srv.BaseURL

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, discoverURL, nil)
	if err != nil {
		t.Fatalf("build discover request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("failed to call /ocm-aux/discover: %v", err)
	}

	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Errorf("close response body: %v", closeErr)
	}

	// Second request should be rate-limited (limit is 1).
	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, discoverURL, nil)
	if err != nil {
		t.Fatalf("build discover request: %v", err)
	}

	resp, err = http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("failed to call /ocm-aux/discover: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusTooManyRequests {
		srv.DumpLogs(t)
		t.Fatalf("expected status 429, got %d", resp.StatusCode)
	}

	requireRetryAfterPositive(t, resp)

	// Ensure other ocmaux endpoints are not rate limited.
	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, srv.BaseURL+"/ocm-aux/federations", nil)
	if err != nil {
		t.Fatalf("build federations request: %v", err)
	}

	resp, err = http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("failed to call /ocm-aux/federations: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		srv.DumpLogs(t)
		t.Fatalf("expected status 200 for /ocm-aux/federations, got %d", resp.StatusCode)
	}
}

func TestRateLimitAPILogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	extraConfig := `
[http.interceptors.ratelimit.profiles.login]
requests_per_window = 1
window_seconds = 60

[http.services.api.ratelimit]
profile = "login"
`

	binaryPath := harness.BuildBinary(t)

	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:        "ratelimit-api",
		Mode:        "dev",
		ExtraConfig: extraConfig,
	})
	defer srv.Stop(t)

	loginURL := srv.BaseURL + "/api/auth/login"
	firstResp := postLogin(t, loginURL)

	if closeErr := firstResp.Body.Close(); closeErr != nil {
		t.Errorf("close response body: %v", closeErr)
	}

	resp := postLogin(t, loginURL) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusTooManyRequests {
		srv.DumpLogs(t)
		t.Fatalf("expected status 429, got %d", resp.StatusCode)
	}

	requireRetryAfterPositive(t, resp)

	// Ensure other API endpoints are not rate limited.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.BaseURL+"/api/healthz", nil)
	if err != nil {
		t.Fatalf("build healthz request: %v", err)
	}

	resp, err = http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("failed to call /api/healthz: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		srv.DumpLogs(t)
		t.Fatalf("expected status 200 for /api/healthz, got %d", resp.StatusCode)
	}
}

func postLogin(t *testing.T, url string) *http.Response {
	t.Helper()

	body := bytes.NewBufferString(`{"username":"admin","password":"wrong"}`)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, body)
	if err != nil {
		t.Fatalf("failed to build POST /api/auth/login request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to POST /api/auth/login: %v", err)
	}

	return resp
}

func requireRetryAfterPositive(t *testing.T, resp *http.Response) {
	t.Helper()

	retryAfter := resp.Header.Get("Retry-After")
	if retryAfter == "" {
		t.Fatalf("expected Retry-After header to be set")
	}

	seconds, err := strconv.Atoi(retryAfter)
	if err != nil {
		t.Fatalf("expected Retry-After to be integer seconds, got %q", retryAfter)
	}

	if seconds < 1 {
		t.Fatalf("expected positive Retry-After, got %d", seconds)
	}
}
