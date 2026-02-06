// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Developer-local Pebble e2e test for real ACME issuance.
//
// Requires:
//   - OCM_ACME_PEBBLE_E2E=1  (skipped otherwise)
//   - Pebble running at https://localhost:14000/dir
//   - pebble-challtestsrv running (HTTP-01 validation on port 5002)
//   - PEBBLE_MINICA_PEM pointing to pebble.minica.pem from the Pebble repo
//
// Port 5002: Pebble's validation authority expects to reach the HTTP-01
// challenge on this port. Our server must bind to it so the VA can validate.

package integration

import (
	cryptotls "crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestACME_PebbleE2E performs a real ACME certificate issuance against a
// local Pebble server. Skipped by default; set OCM_ACME_PEBBLE_E2E=1 and
// have Pebble + challtestsrv running.
func TestACME_PebbleE2E(t *testing.T) {
	if os.Getenv("OCM_ACME_PEBBLE_E2E") != "1" {
		t.Skip("set OCM_ACME_PEBBLE_E2E=1 to run Pebble e2e test")
	}

	// Pebble's minica root cert is needed so our server trusts the Pebble
	// directory endpoint (HTTPS). Developer sets the env var to the path.
	minicaPEM := os.Getenv("PEBBLE_MINICA_PEM")
	if minicaPEM == "" {
		t.Skip("PEBBLE_MINICA_PEM not set; point it at pebble.minica.pem")
	}
	if _, err := os.Stat(minicaPEM); err != nil {
		t.Skipf("PEBBLE_MINICA_PEM file not found: %v", err)
	}

	// Verify Pebble is reachable.
	pebbleClient := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &cryptotls.Config{InsecureSkipVerify: true},
		},
	}
	if _, err := pebbleClient.Get("https://localhost:14000/dir"); err != nil {
		t.Skipf("Pebble not reachable at https://localhost:14000/dir: %v", err)
	}

	binaryPath := harness.BuildBinary(t)

	tempDir := t.TempDir()
	acmeDir := filepath.Join(tempDir, "acme")
	if err := os.MkdirAll(acmeDir, 0755); err != nil {
		t.Fatal(err)
	}

	// No pre-generated certs: lego must obtain one from Pebble.
	// Port 5002 is Pebble's default HTTP-01 validation port.
	const httpPort = 5002
	httpsPort := getFreeTCPPort(t)

	configPath := filepath.Join(tempDir, "config.toml")
	configContent := fmt.Sprintf(`# Pebble e2e test config
mode = "dev"
listen_addr = "127.0.0.1:0"
public_origin = "https://localhost:%d"
external_base_path = ""

[tls]
mode = "acme"
http_port = %d
https_port = %d

[tls.acme]
storage_dir = %q
domain = "localhost"
email = "pebble-e2e@test.local"
directory = "https://localhost:14000/dir"

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
tls_root_ca_file = %q

[signature]
inbound_mode = "off"
outbound_mode = "off"
advertise_http_request_signatures = false
`, httpsPort, httpPort, httpsPort, acmeDir, minicaPEM)

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(tempDir, "server.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binaryPath, "--config", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = tempDir

	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("failed to start binary: %v", err)
	}

	var shutdownDone bool
	t.Cleanup(func() {
		if !shutdownDone {
			cmd.Process.Kill()
			cmd.Wait() //nolint:errcheck // best-effort cleanup
		}
		logFile.Close()
		if t.Failed() {
			content, _ := os.ReadFile(logPath)
			t.Logf("=== server logs ===\n%s\n=== end ===", content)
		}
	})

	// ACME issuance can take several seconds; use a longer timeout.
	httpsAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)
	if !waitForTCPListener(t, httpsAddr, 30*time.Second) {
		content, _ := os.ReadFile(logPath)
		t.Fatalf("HTTPS listener did not come up on %s\n=== logs ===\n%s", httpsAddr, content)
	}

	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)

	// 1. Cert files were written by lego after issuance.
	certFile := filepath.Join(acmeDir, "cert.pem")
	keyFile := filepath.Join(acmeDir, "key.pem")
	if _, err := os.Stat(certFile); err != nil {
		t.Errorf("cert.pem not found after issuance: %v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Errorf("key.pem not found after issuance: %v", err)
	}

	// 2. HTTPS healthz returns 200 (using InsecureSkipVerify because the
	// Pebble-issued cert chain is not in our system trust store).
	tlsClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &cryptotls.Config{InsecureSkipVerify: true},
	}}
	resp, err := tlsClient.Get(fmt.Sprintf("https://%s/api/healthz", httpsAddr))
	if err != nil {
		t.Fatalf("HTTPS healthz request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for healthz, got %d", resp.StatusCode)
	}

	// 3. Challenge handler returns 404 for an unknown token.
	resp, err = http.Get(fmt.Sprintf("http://%s/.well-known/acme-challenge/bogus", httpAddr))
	if err != nil {
		t.Fatalf("challenge request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for bogus challenge, got %d", resp.StatusCode)
	}

	// 4. Non-challenge HTTP returns 308 redirect.
	noRedirectClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err = noRedirectClient.Get(fmt.Sprintf("http://%s/some/path?q=1", httpAddr))
	if err != nil {
		t.Fatalf("redirect request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("expected 308, got %d", resp.StatusCode)
	}

	// 5. Clean shutdown.
	cmd.Process.Signal(os.Interrupt)
	exitDone := make(chan error, 1)
	go func() { exitDone <- cmd.Wait() }()
	select {
	case <-exitDone:
		shutdownDone = true
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		<-exitDone
		shutdownDone = true
		t.Fatal("server did not exit within 5 seconds after SIGINT")
	}
}
