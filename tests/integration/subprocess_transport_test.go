// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestSubprocessTransportFollowsExtraConfigTLS guards against a subprocess
// harness regression: the harness must derive BaseURL and the readiness probe
// scheme from the FINAL effective config, not just the preset inputs.
//
// The "dev" preset implies plain HTTP, so the preset-derived transport is http.
// The test then overrides TLS via ExtraConfig ([tls] mode = "selfsigned"), which
// makes the real listener serve HTTPS. If the harness still picked the scheme
// from the preset inputs, it would expose an http:// BaseURL and probe http
// against an https listener, so StartSubprocessServer would fail readiness.
// With the fix the harness loads the rendered config.toml, sees tls.mode =
// selfsigned, and uses https for both BaseURL and the readiness probe.
func TestSubprocessTransportFollowsExtraConfigTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "tls-override",
		Mode:                  "dev",
		KeepSignatureDefaults: true,
		// Override the preset HTTP transport with self-signed HTTPS. The "dev"
		// preset resolves compatibility_scope=unbounded, so selfsigned TLS is
		// permitted by the loader guardrails.
		ExtraConfig: `
[tls]
mode = "selfsigned"
`,
	})
	defer srv.Stop(t)

	if !strings.HasPrefix(srv.BaseURL, "https://localhost:") {
		t.Fatalf("BaseURL should follow the overriding TLS config (https), got %q", srv.BaseURL)
	}

	resp, err := srv.Client().Get(srv.BaseURL + "/api/healthz")
	if err != nil {
		t.Fatalf("health check against overridden TLS listener failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected healthz 200 over https listener, got %d", resp.StatusCode)
	}
}
