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
	if !strings.Contains(outputText, "compatibility_scope=none requires signature.outbound_mode=strict") {
		t.Fatalf("expected strict contradiction error in output, got: %s", outputText)
	}
}

func TestStrictModeRejectsTokenOnlyAtStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	config := `mode = "strict"
listen_addr = "127.0.0.1:0"
public_origin = "http://localhost:9203"
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
outbound_mode = "token-only"
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cmd := exec.Command(binaryPath, "--config", configPath)
	cmd.Dir = tempDir
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected startup failure for strict token-only posture, got success: %s", output)
	}

	outputText := string(output)
	if !strings.Contains(outputText, "compatibility_scope=none requires signature.outbound_mode=strict") {
		t.Fatalf("expected strict token-only error in output, got: %s", outputText)
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
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	config := `mode = "strict"
listen_addr = "127.0.0.1:0"
public_origin = "https://localhost:9204"
external_base_path = ""

[tls]
mode = "selfsigned"

[server]
trusted_proxies = ["127.0.0.0/8", "::1/128"]

[server.bootstrap_admin]
username = "admin"

[outbound_http]
timeout_ms = 5000
connect_timeout_ms = 2000
max_redirects = 1
max_response_bytes = 1048576
insecure_skip_verify = false

[peer_trust]
enabled = true
config_paths = ["trust-group.json"]

[peer_trust.policy]
global_enforce = false
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "trust-group.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write trust-group.json: %v", err)
	}

	cmd := exec.Command(binaryPath, "--config", configPath)
	cmd.Dir = tempDir
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected startup failure for strict fail-open peer trust, got success: %s", output)
	}

	outputText := string(output)
	if !strings.Contains(outputText, "compatibility_scope=none requires peer_trust.policy.global_enforce=true") {
		t.Fatalf("expected strict peer-trust contradiction error in output, got: %s", outputText)
	}
}

func TestCompatModeTokenOnlyDemotesRuntimePosture(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "compat-token-only",
		Mode:                  "compat",
		KeepSignatureDefaults: true,
		ExtraConfig: `
[signature]
outbound_mode = "token-only"
`,
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
	logs := waitForLogSubstrings(t, logPath,
		"token-only",
		"resolved runtime posture is non-strict",
		"signature_outbound_mode_not_strict",
	)
	if logs == "" {
		t.Fatalf("expected token-only runtime posture log")
	}
}

func TestScopedCompatibilityRejectsTokenOnlyAtStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	config := `mode = "strict"
compatibility_scope = "scoped"
listen_addr = "127.0.0.1:0"
public_origin = "https://localhost:9206"
external_base_path = ""

[tls]
mode = "selfsigned"

[server]
trusted_proxies = ["127.0.0.0/8", "::1/128"]

[server.bootstrap_admin]
username = "admin"

[signature]
outbound_mode = "token-only"
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cmd := exec.Command(binaryPath, "--config", configPath)
	cmd.Dir = tempDir
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected startup failure for scoped token-only posture, got success: %s", output)
	}

	outputText := string(output)
	if !strings.Contains(outputText, "compatibility_scope=scoped requires signature.outbound_mode=strict") {
		t.Fatalf("expected scoped token-only error in output, got: %s", outputText)
	}
}

func TestScopedCompatibilityMappedGrantOverrideDemotesRuntimePosture(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "scoped-grant-override",
		Mode:                  "strict",
		CompatibilityScope:    "scoped",
		KeepSignatureDefaults: true,
		ExtraConfig: `
[signature]
peer_profile_level_override = "non-strict"

[[peer_profiles.mappings]]
pattern = "peer.example.com"
profile = "grant-compat"

[peer_profiles.custom_profiles.grant-compat]
token_exchange_grant_type = "ocm_share"
`,
	})
	defer srv.Stop(t)

	// srv.Client() returns an insecure client to accept the self-signed cert
	// used by selfsigned TLS mode; the server config itself enforces strict TLS.
	resp, err := srv.Client().Get(srv.BaseURL + "/api/healthz")
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected healthz 200, got %d", resp.StatusCode)
	}

	logPath := filepath.Join(srv.TempDir, "server.log")
	logs := waitForLogSubstrings(t, logPath,
		"resolved runtime posture is non-strict",
		"compatibility_scope",
		"scoped",
		"peer_profile_relaxations_active",
	)
	if logs == "" {
		t.Fatalf("expected compiled-summary posture log for mapped grant override")
	}
}

func waitForLogSubstrings(t *testing.T, logPath string, want ...string) string {
	t.Helper()

	var logs string
	for i := 0; i < 20; i++ {
		content, readErr := os.ReadFile(logPath)
		if readErr != nil {
			t.Fatalf("failed to read server log: %v", readErr)
		}
		logs = string(content)

		allPresent := true
		for _, needle := range want {
			if !strings.Contains(logs, needle) {
				allPresent = false
				break
			}
		}
		if allPresent {
			return logs
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("expected log to contain %v, got logs:\n%s", want, logs)
	return ""
}
