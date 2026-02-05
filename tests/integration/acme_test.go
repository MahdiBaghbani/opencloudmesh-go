// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

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
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestACME_SubprocessTwoListeners starts the real binary in ACME mode and
// verifies both the HTTP (challenge + redirect) and HTTPS (application)
// listeners. Pre-generated certs mean zero ACME network calls.
func TestACME_SubprocessTwoListeners(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)

	// Temp dir for the server's working data.
	tempDir := t.TempDir()

	// Write cert.pem and key.pem so ACMEManager.Init takes the fast path.
	acmeDir := filepath.Join(tempDir, "acme")
	if err := os.MkdirAll(acmeDir, 0755); err != nil {
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

[signature]
inbound_mode = "off"
outbound_mode = "off"
advertise_http_request_signatures = false
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

	cmd := exec.Command(binaryPath, "--config", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = tempDir

	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("failed to start binary: %v", err)
	}

	// Cleanup: always dump logs and kill process.
	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Signal(os.Interrupt)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				cmd.Process.Kill()
				<-done
			}
		}
		logFile.Close()
		if t.Failed() {
			content, _ := os.ReadFile(logPath)
			t.Logf("=== server logs ===\n%s\n=== end ===", content)
		}
	})

	// Wait for HTTPS listener to come up.
	httpsAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)
	if !waitForTCPListener(t, httpsAddr, 15*time.Second) {
		content, _ := os.ReadFile(logPath)
		t.Fatalf("HTTPS listener did not come up on %s\n=== logs ===\n%s", httpsAddr, content)
	}

	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)

	// 1. Challenge handler returns 404 for unknown token.
	resp, err := http.Get(fmt.Sprintf("http://%s/.well-known/acme-challenge/nonexistent", httpAddr))
	if err != nil {
		t.Fatalf("challenge request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for unknown challenge, got %d", resp.StatusCode)
	}

	// 2. Non-challenge HTTP request returns 308 redirect to HTTPS.
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
	loc := resp.Header.Get("Location")
	wantLoc := fmt.Sprintf("https://127.0.0.1:%d/some/path?q=1", httpsPort)
	if loc != wantLoc {
		t.Errorf("redirect Location = %q, want %q", loc, wantLoc)
	}

	// 3. HTTPS listener serves the application (healthz returns 200).
	tlsClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &cryptotls.Config{InsecureSkipVerify: true},
	}}
	resp, err = tlsClient.Get(fmt.Sprintf("https://%s/api/healthz", httpsAddr))
	if err != nil {
		t.Fatalf("HTTPS healthz request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for healthz, got %d", resp.StatusCode)
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
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
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
	keyDER, _ := x509.MarshalECPrivateKey(key)
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
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("getFreeTCPPort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// waitForTCPListener polls a TCP address until it accepts or timeout expires.
func waitForTCPListener(t *testing.T, addr string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
