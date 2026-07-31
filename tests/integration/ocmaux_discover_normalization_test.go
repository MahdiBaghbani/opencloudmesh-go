// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

const discoverTargetInviteDialogExtraConfig = `
[http.services.ui]
[http.services.ui.wayf]
enabled = true
[http.services.ui.invite_accept]
enabled = true
`

func TestOCMAuxDiscover_PastedPathNormalization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)

	target := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:        "discover-target",
		Mode:        "dev",
		ExtraConfig: discoverTargetInviteDialogExtraConfig,
	})
	defer target.Stop(t)

	source := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "discover-source",
		Mode: "dev",
	})
	defer source.Stop(t)

	discoverURL := source.BaseURL + "/ocm-aux/discover?base=" + target.BaseURL + "/apps/files/files/123"

	resp, err := http.Get(discoverURL)
	if err != nil {
		source.DumpLogs(t)
		target.DumpLogs(t)
		t.Fatalf("discover request failed: %v", err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		source.DumpLogs(t)
		target.DumpLogs(t)
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if !body.Success {
		t.Fatal("expected success=true for pasted-path discover")
	}
}

func TestOCMAuxDiscover_BareHostNormalization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)

	target := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:        "discover-target",
		Mode:        "dev",
		ExtraConfig: discoverTargetInviteDialogExtraConfig,
	})
	defer target.Stop(t)

	source := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "discover-source",
		Mode: "dev",
	})
	defer source.Stop(t)

	host := strings.TrimPrefix(strings.TrimPrefix(target.BaseURL, "https://"), "http://")
	discoverURL := source.BaseURL + "/ocm-aux/discover?base=" + host

	resp, err := http.Get(discoverURL)
	if err != nil {
		source.DumpLogs(t)
		target.DumpLogs(t)
		t.Fatalf("discover request failed: %v", err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest {
		source.DumpLogs(t)
		t.Fatalf("bare host should not be rejected as invalid_url, got 400")
	}

	var body struct {
		Success    bool   `json:"success"`
		ReasonCode string `json:"reasonCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.ReasonCode == "invalid_url" {
		t.Fatalf("bare host normalized input must not return invalid_url")
	}
}

func TestOCMAuxDiscover_SSRFBlockedFriendlyReason(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)

	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "discover-ssrf",
		Mode: "strict",
	})
	defer srv.Stop(t)

	discoverURL := srv.BaseURL + "/ocm-aux/discover?base=http://10.0.0.1:8080"

	resp, err := srv.Client().Get(discoverURL)
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("discover request failed: %v", err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		srv.DumpLogs(t)
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	var body struct {
		Success    bool   `json:"success"`
		Error      string `json:"error"`
		ReasonCode string `json:"reasonCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.Success {
		t.Fatal("expected success=false")
	}

	if body.ReasonCode != "ssrf_blocked" {
		t.Fatalf("reasonCode = %q, want ssrf_blocked", body.ReasonCode)
	}

	if body.Error == "" {
		t.Fatal("expected friendly error message")
	}

	if strings.Contains(body.Error, "private IP") || strings.Contains(body.Error, "CIDR") {
		t.Fatalf("user-facing error leaked SSRF details: %q", body.Error)
	}
}

func TestOCMAuxDiscover_NoInviteAcceptDialogReason(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)

	target := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "discover-no-dialog-target",
		Mode: "dev",
	})
	defer target.Stop(t)

	source := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "discover-no-dialog-source",
		Mode: "dev",
	})
	defer source.Stop(t)

	discoverURL := source.BaseURL + "/ocm-aux/discover?base=" + target.BaseURL

	resp, err := http.Get(discoverURL)
	if err != nil {
		source.DumpLogs(t)
		target.DumpLogs(t)
		t.Fatalf("discover request failed: %v", err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		source.DumpLogs(t)
		target.DumpLogs(t)
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}

	var body struct {
		Success    bool   `json:"success"`
		Error      string `json:"error"`
		ReasonCode string `json:"reasonCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.Success {
		t.Fatal("expected success=false")
	}

	if body.ReasonCode != "no_invite_accept_dialog" {
		t.Fatalf("reasonCode = %q, want no_invite_accept_dialog", body.ReasonCode)
	}

	if body.Error == "" {
		t.Fatal("expected friendly error message")
	}
}
