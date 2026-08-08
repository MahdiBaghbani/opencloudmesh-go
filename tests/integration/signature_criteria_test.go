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

func TestSignatureCriteria(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("criteria off allows unsigned token request", func(t *testing.T) {
		t.Parallel()

		falseVal := false

		ts := harness.StartTestServerWithIETFConfig(t, func(cfg *config.Config) {
			cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures = &falseVal
		})
		defer ts.Stop(t)

		status, body := postUnsignedToken(t, ts.BaseURL)
		if status != http.StatusBadRequest {
			t.Fatalf("criteria-off: status = %d, body = %q; want 400", status, body)
		}

		if !strings.Contains(body, "invalid_grant") {
			t.Fatalf("criteria-off: status = %d, body = %q; want it to contain invalid_grant", status, body)
		}
	})

	t.Run("criteria on rejects unsigned token request", func(t *testing.T) {
		t.Parallel()

		trueVal := true

		ts := harness.StartTestServerWithIETFConfig(t, func(cfg *config.Config) {
			cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures = &trueVal
		})
		defer ts.Stop(t)

		status, body := postUnsignedToken(t, ts.BaseURL)
		if status != http.StatusUnauthorized {
			t.Fatalf("criteria-on: status = %d, body = %q; want 401", status, body)
		}
	})
}

func postUnsignedToken(t *testing.T, baseURL string) (int, string) {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "client.example.com")
	form.Set("code", "unused-code")

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		baseURL+"/ocm/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("build unsigned token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("post unsigned token request: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read token response body: %v", err)
	}

	return resp.StatusCode, string(body)
}
