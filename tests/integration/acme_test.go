// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestACME_SubprocessTwoListeners starts the real binary in ACME mode and
// verifies both the HTTP (challenge + redirect) and HTTPS (application)
// listeners. Pre-generated certs mean zero ACME network calls.
//
// The generated config leaves [signature] unset so the dev preset's strict
// inbound/outbound defaults apply; this test only exercises the ACME/TLS
// listener setup, not signature enforcement.
func TestACME_SubprocessTwoListeners(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)

	// Temp dir for the server's working data.
	tempDir := t.TempDir()

	// Write cert.pem and key.pem so ACMEManager.Init takes the fast path.
	acmeDir := filepath.Join(tempDir, "acme")
	if err := os.MkdirAll(acmeDir, 0755); err != nil { //nolint:gosec // test fixture: 0755 on a local controlled test temp dir, not an attacker-controlled production path
		t.Fatal(err)
	}

	writeTestCert(t, acmeDir)

	httpPort := getFreeTCPPort(t)
	httpsPort := getFreeTCPPort(t)

	configPath := filepath.Join(tempDir, "config.toml")
	configContent := fmt.Sprintf(`# ACME integration test config
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
email = "test@test.local"
directory = "https://192.0.2.1:14000/dir"

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
`, httpsPort, httpPort, httpsPort, acmeDir)

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Start subprocess.
	logPath := filepath.Join(tempDir, "server.log")

	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}

	// t.Context backstops the cleanup kill; gracefulShutdown stays the primary
	// shutdown path because it runs before the test context is canceled.
	cmd := exec.CommandContext(t.Context(), binaryPath, "--config", configPath) //nolint:gosec // test harness: intentional subprocess launch with test-controlled args
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = tempDir

	if err := cmd.Start(); err != nil {
		mustClose(t, logFile)
		t.Fatalf("failed to start binary: %v", err)
	}

	// Safety net: kill process if the test fails before the explicit
	// shutdown assertion at the end.
	var shutdownDone bool

	t.Cleanup(func() {
		if !shutdownDone {
			if killErr := cmd.Process.Kill(); killErr != nil {
				t.Logf("cleanup kill: %v", killErr)
			}

			if waitErr := cmd.Wait(); waitErr != nil {
				t.Logf("cleanup wait: %v", waitErr)
			}
		}

		mustClose(t, logFile)

		if t.Failed() {
			t.Logf("=== server logs ===\n%s\n=== end ===", readLogOrFail(t, logPath))
		}
	})

	// Wait for HTTPS listener to come up.
	httpsAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)

	if !waitForTCPListener(t, httpsAddr, 15*time.Second) {
		t.Fatalf("HTTPS listener did not come up on %s\n=== logs ===\n%s", httpsAddr, readLogOrFail(t, logPath))
	}

	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)

	// 1. Challenge handler returns 404 for unknown token.
	assertHTTPStatus(
		t,
		"challenge",
		http.DefaultClient,
		fmt.Sprintf("http://%s/.well-known/acme-challenge/nonexistent", httpAddr),
		http.StatusNotFound,
	)

	// 2. Non-challenge HTTP request returns 308 redirect to HTTPS.
	assertRedirectToHTTPS(t, httpAddr, httpsPort)

	// 3. HTTPS listener serves the application (healthz returns 200).
	tlsClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &cryptotls.Config{InsecureSkipVerify: true}, //nolint:gosec // test TLS client: InsecureSkipVerify against self-signed test CA
	}}

	assertHTTPStatus(
		t,
		"healthz",
		tlsClient,
		fmt.Sprintf("https://%s/api/healthz", httpsAddr),
		http.StatusOK,
	)

	// 4. Clean shutdown: SIGINT triggers graceful exit within 5 seconds.
	shutdown := gracefulShutdown(t, cmd)
	shutdownDone = true

	if !shutdown {
		t.Fatal("server did not exit within 5 seconds after SIGINT")
	}
}

// readLogOrFail returns the subprocess log contents.
func readLogOrFail(t *testing.T, logPath string) string {
	t.Helper()

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	return string(content)
}

// assertHTTPStatus fetches url with client and expects wantStatus. The name
// labels failure output so probe failures stay attributable.
func assertHTTPStatus(t *testing.T, name string, client *http.Client, url string, wantStatus int) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("%s: build request: %v", name, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s request failed: %v", name, err)
	}

	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Errorf("%s: close response body: %v", name, closeErr)
	}

	if resp.StatusCode != wantStatus {
		t.Errorf("%s: expected %d, got %d", name, wantStatus, resp.StatusCode)
	}
}

// assertRedirectToHTTPS fetches an HTTP URL without following redirects and
// expects a 308 to the corresponding HTTPS URL.
func assertRedirectToHTTPS(t *testing.T, httpAddr string, httpsPort int) {
	t.Helper()

	noRedirectClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		fmt.Sprintf("http://%s/some/path?q=1", httpAddr),
		nil,
	)
	if err != nil {
		t.Fatalf("build redirect request: %v", err)
	}

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("redirect request failed: %v", err)
	}

	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Errorf("close response body: %v", closeErr)
	}

	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("expected 308, got %d", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	wantLoc := fmt.Sprintf("https://127.0.0.1:%d/some/path?q=1", httpsPort)

	if loc != wantLoc {
		t.Errorf("redirect Location = %q, want %q", loc, wantLoc)
	}
}

// gracefulShutdown sends SIGINT and waits for the process to exit, killing it
// after tshttp.DefaultShutdownWait. It reports whether the process exited on
// its own.
func gracefulShutdown(t *testing.T, cmd *exec.Cmd) bool {
	t.Helper()

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Logf("signal interrupt: %v", err)
	}

	exitDone := make(chan error, 1)
	go func() { exitDone <- cmd.Wait() }()

	select {
	case <-exitDone:
		return true
	case <-time.After(tshttp.DefaultShutdownWait):
		if err := cmd.Process.Kill(); err != nil {
			t.Logf("kill after shutdown timeout: %v", err)
		}

		<-exitDone

		return false
	}
}

// mustClose closes c and reports a test error when close fails.
func mustClose(t *testing.T, c io.Closer) {
	t.Helper()

	if err := c.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// writeTestCert generates a self-signed cert+key pair and writes cert.pem
// and key.pem into dir.
func writeTestCert(t *testing.T, dir string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
}

// getFreeTCPPort binds to :0, grabs the port, and releases it.
func getFreeTCPPort(t *testing.T) int {
	t.Helper()

	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("getFreeTCPPort: %v", err)
	}

	tcpAddr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("getFreeTCPPort: unexpected addr type %T", l.Addr())
	}

	port := tcpAddr.Port

	mustClose(t, l)

	return port
}

// waitForTCPListener polls a TCP address until it accepts or timeout expires.
func waitForTCPListener(t *testing.T, addr string, timeout time.Duration) bool {
	t.Helper()

	deadline := time.Now().Add(timeout)
	dialer := &net.Dialer{Timeout: 200 * time.Millisecond}

	for time.Now().Before(deadline) {
		conn, err := dialer.DialContext(t.Context(), "tcp", addr)
		if err == nil {
			mustClose(t, conn)
			return true
		}

		time.Sleep(100 * time.Millisecond)
	}

	return false
}
