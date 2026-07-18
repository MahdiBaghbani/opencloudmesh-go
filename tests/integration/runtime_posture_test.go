// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
	if !strings.Contains(outputText, "invalid signature.outbound_mode") {
		t.Fatalf("expected retired outbound_mode enum error in output, got: %s", outputText)
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
	if !strings.Contains(outputText, "invalid signature.outbound_mode") {
		t.Fatalf("expected retired outbound_mode enum error in output, got: %s", outputText)
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
inbound_mode = "strict"
outbound_mode = "strict"
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
		!strings.Contains(outputText, "unsupported keys") {
		t.Fatalf("expected unsupported-key error in output, got: %s", outputText)
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

// TestCompatModeTokenOnlyRejectedAtStartup verifies that compat mode rejects
// retired signature.outbound_mode=token-only at startup (strict is the sole
// loadable outbound value).
func TestCompatModeTokenOnlyRejectedAtStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	config := `mode = "compat"
listen_addr = "127.0.0.1:0"
public_origin = "https://localhost:9209"
external_base_path = ""

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
		t.Fatalf("expected startup failure for compat scoped token-only posture, got success: %s", output)
	}

	outputText := string(output)
	if !strings.Contains(outputText, "invalid signature.outbound_mode") {
		t.Fatalf("expected retired outbound_mode enum error in output, got: %s", outputText)
	}
}

func TestNoneScopePeerProfileMappingsRejectedAtStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	config := `mode = "strict"
listen_addr = "127.0.0.1:0"
public_origin = "https://localhost:9207"
external_base_path = ""

[tls]
mode = "selfsigned"

[server]
trusted_proxies = ["127.0.0.0/8", "::1/128"]

[server.bootstrap_admin]
username = "admin"

[[peer_profiles.mappings]]
pattern = "peer.example.com"
profile = "some-compat"
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cmd := exec.Command(binaryPath, "--config", configPath)
	cmd.Dir = tempDir
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected startup failure for peer_profiles.mappings under none, got success: %s", output)
	}

	outputText := string(output)
	if !strings.Contains(outputText, "compatibility_scope=none forbids peer_profiles.mappings") {
		t.Fatalf("expected peer_profiles.mappings rejection error in output, got: %s", outputText)
	}
}

func TestNoneScopeRequireTokenExchangeFalseRejectedAtStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	config := `mode = "strict"
listen_addr = "127.0.0.1:0"
public_origin = "https://localhost:9208"
external_base_path = ""
require_token_exchange = false

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
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cmd := exec.Command(binaryPath, "--config", configPath)
	cmd.Dir = tempDir
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected startup failure for require_token_exchange=false under none scope, got success: %s", output)
	}

	outputText := string(output)
	if !strings.Contains(outputText, "compatibility_scope=none requires require_token_exchange=true") {
		t.Fatalf("expected none-scope require_token_exchange error in output, got: %s", outputText)
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
	if !strings.Contains(outputText, "invalid signature.outbound_mode") {
		t.Fatalf("expected retired outbound_mode enum error in output, got: %s", outputText)
	}
}
