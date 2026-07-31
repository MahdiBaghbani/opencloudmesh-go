// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestACME_PebbleE2E performs a real ACME certificate issuance against a
// local Pebble server. Skipped by default; set OCM_ACME_PEBBLE_E2E=1 and
// have Pebble + challtestsrv running.
func TestACME_PebbleE2E(t *testing.T) {
	minicaPEM := requirePebbleMinica(t)
	probePebbleDirectory(t)

	binaryPath := harness.BuildBinary(t)

	tempDir := t.TempDir()

	acmeDir := filepath.Join(tempDir, "acme")

	if err := os.MkdirAll(acmeDir, 0755); err != nil { //nolint:gosec // test fixture: 0755 on a local controlled test temp dir, not an attacker-controlled production path
		t.Fatal(err)
	}

	// No pre-generated certs: lego must obtain one from Pebble.
	// Port 5002 is Pebble's default HTTP-01 validation port.
	const httpPort = 5002

	httpsPort := getFreeTCPPort(t)
	configPath := writePebbleE2EConfig(t, tempDir, acmeDir, minicaPEM, httpPort, httpsPort)

	srv := startPebbleE2EServer(t, binaryPath, configPath, tempDir)

	// ACME issuance can take several seconds; use a longer timeout.
	httpsAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)
	srv.waitForListener(t, httpsAddr, 30*time.Second)

	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)

	assertIssuedCertFiles(t, acmeDir)
	assertHTTPSHealthz(t, httpsAddr)
	assertUnknownChallengeNotFound(t, httpAddr)
	assertPlainHTTPRedirects(t, httpAddr)
	srv.shutdown(t)
}

// requirePebbleMinica returns the developer-provided Pebble minica root path
// or skips the test when the e2e prerequisites are not set up.
func requirePebbleMinica(t *testing.T) string {
	t.Helper()

	if os.Getenv("OCM_ACME_PEBBLE_E2E") != "1" {
		t.Skip("set OCM_ACME_PEBBLE_E2E=1 to run Pebble e2e test")
	}

	// Pebble's minica root cert is needed so our server trusts the Pebble
	// directory endpoint (HTTPS). Developer sets the env var to the path.
	minicaPEM := os.Getenv("PEBBLE_MINICA_PEM")
	if minicaPEM == "" {
		t.Skip("PEBBLE_MINICA_PEM not set; point it at pebble.minica.pem")
	}

	if _, err := os.Stat(minicaPEM); err != nil { //nolint:gosec // test fixture: path comes from the developer-set PEBBLE_MINICA_PEM env var, not attacker-controlled input
		t.Skipf("PEBBLE_MINICA_PEM file not found: %v", err)
	}

	return minicaPEM
}

// probePebbleDirectory skips the test when the local Pebble directory
// endpoint is not reachable.
func probePebbleDirectory(t *testing.T) {
	t.Helper()

	pebbleClient := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &cryptotls.Config{InsecureSkipVerify: true}, //nolint:gosec // test TLS client: InsecureSkipVerify against self-signed test CA
		},
	}

	pebbleReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://localhost:14000/dir", nil)
	if err != nil {
		t.Fatalf("build Pebble probe request: %v", err)
	}

	resp, err := pebbleClient.Do(pebbleReq) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer tshttp.MustClose(t, resp.Body)
	}

	if err != nil {
		t.Skipf("Pebble not reachable at https://localhost:14000/dir: %v", err)
	}
}

// writePebbleE2EConfig renders the dev-mode ACME config for the Pebble run
// and returns its path.
func writePebbleE2EConfig(t *testing.T, tempDir, acmeDir, minicaPEM string, httpPort, httpsPort int) string {
	t.Helper()

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
`, httpsPort, httpPort, httpsPort, acmeDir, minicaPEM)

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	return configPath
}

// pebbleE2EServer tracks the running server subprocess so the explicit
// SIGINT shutdown and the test cleanup do not race each other.
type pebbleE2EServer struct {
	cmd          *exec.Cmd
	logFile      *os.File
	logPath      string
	shutdownDone bool
}

// startPebbleE2EServer launches the server binary against the Pebble config
// and registers the failure-dumping cleanup.
func startPebbleE2EServer(t *testing.T, binaryPath, configPath, tempDir string) *pebbleE2EServer {
	t.Helper()

	logPath := filepath.Join(tempDir, "server.log")

	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}

	// t.Context backstops the cleanup kill; the explicit SIGINT shutdown stays
	// the primary path because it runs before the test context is canceled.
	cmd := exec.CommandContext(t.Context(), binaryPath, "--config", configPath) //nolint:gosec // test harness: intentional subprocess launch with test-controlled args
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = tempDir

	if startErr := cmd.Start(); startErr != nil {
		if closeErr := logFile.Close(); closeErr != nil {
			t.Logf("close log file after start failure: %v", closeErr)
		}

		t.Fatalf("failed to start binary: %v", startErr)
	}

	srv := &pebbleE2EServer{cmd: cmd, logFile: logFile, logPath: logPath}

	t.Cleanup(func() {
		if !srv.shutdownDone {
			if err := cmd.Process.Kill(); err != nil {
				t.Logf("kill subprocess: %v", err)
			}

			// Wait reports the kill signal after Kill; log, do not fail.
			if err := cmd.Wait(); err != nil {
				t.Logf("wait for killed subprocess: %v", err)
			}
		}

		if err := logFile.Close(); err != nil {
			t.Errorf("close log file: %v", err)
		}

		if t.Failed() {
			content, readErr := os.ReadFile(logPath)
			if readErr != nil {
				t.Fatalf("read file: %v", readErr)
			}

			t.Logf("=== server logs ===\n%s\n=== end ===", content)
		}
	})

	return srv
}

// waitForListener fails the test with the server logs when the HTTPS
// listener does not come up within timeout.
func (srv *pebbleE2EServer) waitForListener(t *testing.T, httpsAddr string, timeout time.Duration) {
	t.Helper()

	if waitForTCPListener(t, httpsAddr, timeout) {
		return
	}

	content, err := os.ReadFile(srv.logPath)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	t.Fatalf("HTTPS listener did not come up on %s\n=== logs ===\n%s", httpsAddr, content)
}

// shutdown SIGINTs the server and fails when it does not exit in time.
func (srv *pebbleE2EServer) shutdown(t *testing.T) {
	t.Helper()

	if err := srv.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Logf("signal SIGINT to subprocess: %v", err)
	}

	exitDone := make(chan error, 1)
	go func() { exitDone <- srv.cmd.Wait() }()

	select {
	case <-exitDone:
		srv.shutdownDone = true
	case <-time.After(tshttp.DefaultShutdownWait):
		if err := srv.cmd.Process.Kill(); err != nil {
			t.Logf("kill subprocess after timeout: %v", err)
		}

		<-exitDone

		srv.shutdownDone = true

		t.Fatal("server did not exit within 5 seconds after SIGINT")
	}
}

// mustGet issues a GET request and fails the test on build or transport
// errors; the caller owns closing the response body.
func mustGet(t *testing.T, client *http.Client, url, what string) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build %s request: %v", what, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s request failed: %v", what, err)
	}

	return resp
}

// assertIssuedCertFiles checks that lego wrote the issued cert and key.
func assertIssuedCertFiles(t *testing.T, acmeDir string) {
	t.Helper()

	if _, err := os.Stat(filepath.Join(acmeDir, "cert.pem")); err != nil {
		t.Errorf("cert.pem not found after issuance: %v", err)
	}

	if _, err := os.Stat(filepath.Join(acmeDir, "key.pem")); err != nil {
		t.Errorf("key.pem not found after issuance: %v", err)
	}
}

// assertHTTPSHealthz checks that the ACME-managed HTTPS listener serves
// healthz (using InsecureSkipVerify because the Pebble-issued cert chain is
// not in our system trust store).
func assertHTTPSHealthz(t *testing.T, httpsAddr string) {
	t.Helper()

	tlsClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &cryptotls.Config{InsecureSkipVerify: true}, //nolint:gosec // test TLS client: InsecureSkipVerify against self-signed test CA
	}}

	resp := mustGet(t, tlsClient, fmt.Sprintf("https://%s/api/healthz", httpsAddr), "HTTPS healthz")

	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Errorf("close response body: %v", closeErr)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for healthz, got %d", resp.StatusCode)
	}
}

// assertUnknownChallengeNotFound checks that the challenge handler returns
// 404 for an unknown token.
func assertUnknownChallengeNotFound(t *testing.T, httpAddr string) {
	t.Helper()

	resp := mustGet(t, http.DefaultClient, fmt.Sprintf("http://%s/.well-known/acme-challenge/bogus", httpAddr), "challenge")

	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Errorf("close response body: %v", closeErr)
	}

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for bogus challenge, got %d", resp.StatusCode)
	}
}

// assertPlainHTTPRedirects checks that non-challenge HTTP traffic gets a 308
// redirect to HTTPS.
func assertPlainHTTPRedirects(t *testing.T, httpAddr string) {
	t.Helper()

	noRedirectClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp := mustGet(t, noRedirectClient, fmt.Sprintf("http://%s/some/path?q=1", httpAddr), "redirect")

	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Errorf("close response body: %v", closeErr)
	}

	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("expected 308, got %d", resp.StatusCode)
	}
}
