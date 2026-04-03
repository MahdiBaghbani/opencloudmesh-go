// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func TestStrictModeRejectsSignatureContradictionsAtStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	config := `mode = "strict"
listen_addr = "127.0.0.1:0"
public_origin = "http://localhost:9200"
external_base_path = ""

[tls]
mode = "off"

[server]
trusted_proxies = ["127.0.0.0/8", "::1/128"]

[server.bootstrap_admin]
username = "admin"

[outbound_http]
timeout_ms = 5000
connect_timeout_ms = 2000
max_redirects = 1
max_response_bytes = 1048576
insecure_skip_verify = true

[signature]
outbound_mode = "criteria-only"
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cmd := exec.Command(binaryPath, "--config", configPath)
	cmd.Dir = tempDir
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected startup failure for strict signature contradiction, got success: %s", output)
	}

	outputText := string(output)
	if !strings.Contains(outputText, "mode=strict requires signature.outbound_mode=strict") {
		t.Fatalf("expected strict contradiction error in output, got: %s", outputText)
	}
}

func TestRemovedSignatureAdvertiseRootKeyRejectedAtStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	config := `mode = "dev"
listen_addr = "127.0.0.1:0"
public_origin = "http://localhost:9201"
external_base_path = ""

[tls]
mode = "off"

[server]
trusted_proxies = ["127.0.0.0/8", "::1/128"]

[server.bootstrap_admin]
username = "admin"

[outbound_http]
timeout_ms = 5000
connect_timeout_ms = 2000
max_redirects = 1
max_response_bytes = 1048576
insecure_skip_verify = true

[signature]
inbound_mode = "off"
outbound_mode = "off"
advertise_http_request_signatures = true
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cmd := exec.Command(binaryPath, "--config", configPath)
	cmd.Dir = tempDir
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected startup failure for removed root key, got success: %s", output)
	}

	outputText := string(output)
	if !strings.Contains(outputText, "signature.advertise_http_request_signatures") ||
		!strings.Contains(outputText, "was removed") {
		t.Fatalf("expected removed-root-key error in output, got: %s", outputText)
	}
}

func TestRemovedSignatureAdvertiseCLIFlagRejectedAtStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	config := `mode = "dev"
listen_addr = "127.0.0.1:0"
public_origin = "http://localhost:9202"
external_base_path = ""

[tls]
mode = "off"

[server]
trusted_proxies = ["127.0.0.0/8", "::1/128"]

[server.bootstrap_admin]
username = "admin"

[outbound_http]
timeout_ms = 5000
connect_timeout_ms = 2000
max_redirects = 1
max_response_bytes = 1048576
insecure_skip_verify = true
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cmd := exec.Command(
		binaryPath,
		"--config", configPath,
		"--signature-advertise-http-request-signatures", "true",
	)
	cmd.Dir = tempDir
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected startup failure for removed CLI flag, got success: %s", output)
	}

	outputText := string(output)
	if !strings.Contains(outputText, "flag provided but not defined") ||
		!strings.Contains(outputText, "signature-advertise-http-request-signatures") {
		t.Fatalf("expected removed-flag parse error in output, got: %s", outputText)
	}
}

func TestStrictModePeerTrustFailOpenDemotesRuntimePosture(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "strict-trust-fail-open",
		Mode:                  "strict",
		KeepSignatureDefaults: true,
		ExtraConfig: `
[peer_trust]
enabled = true
config_paths = ["trust-group.json"]

[peer_trust.policy]
global_enforce = false
`,
		ExtraFiles: map[string]string{
			"trust-group.json": "{}",
		},
	})
	defer srv.Stop(t)

	resp, err := http.Get(srv.BaseURL + "/api/healthz")
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected healthz 200, got %d", resp.StatusCode)
	}

	logPath := filepath.Join(srv.TempDir, "server.log")
	var logs string
	for i := 0; i < 20; i++ {
		content, readErr := os.ReadFile(logPath)
		if readErr != nil {
			t.Fatalf("failed to read server log: %v", readErr)
		}
		logs = string(content)
		if strings.Contains(logs, "resolved runtime signature posture is non-strict") &&
			strings.Contains(logs, "trust_status") &&
			strings.Contains(logs, "fail-open") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf(
		"expected non-strict runtime posture log with fail-open trust status, got logs:\n%s",
		logs,
	)
}
