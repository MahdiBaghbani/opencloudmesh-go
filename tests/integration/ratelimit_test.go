// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 OpenCloudMesh Authors

package integration

import (
	"bytes"
	"net/http"
	"strconv"
	"testing"

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
	resp, err := http.Get(discoverURL)
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("failed to call /ocm-aux/discover: %v", err)
	}
	resp.Body.Close()

	// Second request should be rate-limited (limit is 1).
	resp, err = http.Get(discoverURL)
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("failed to call /ocm-aux/discover: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		srv.DumpLogs(t)
		t.Fatalf("expected status 429, got %d", resp.StatusCode)
	}
	requireRetryAfterPositive(t, resp)

	// Ensure other ocmaux endpoints are not rate limited.
	resp, err = http.Get(srv.BaseURL + "/ocm-aux/federations")
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("failed to call /ocm-aux/federations: %v", err)
	}
	defer resp.Body.Close()

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
	resp := postLogin(t, loginURL)
	resp.Body.Close()

	resp = postLogin(t, loginURL)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		srv.DumpLogs(t)
		t.Fatalf("expected status 429, got %d", resp.StatusCode)
	}
	requireRetryAfterPositive(t, resp)

	// Ensure other API endpoints are not rate limited.
	resp, err := http.Get(srv.BaseURL + "/api/healthz")
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("failed to call /api/healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		srv.DumpLogs(t)
		t.Fatalf("expected status 200 for /api/healthz, got %d", resp.StatusCode)
	}
}

func postLogin(t *testing.T, url string) *http.Response {
	t.Helper()

	body := bytes.NewBufferString(`{"username":"admin","password":"wrong"}`)
	resp, err := http.Post(url, "application/json", body)
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
