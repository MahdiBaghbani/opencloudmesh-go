// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Package harness provides test utilities for integration tests.
package harness

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// SubprocessServer represents a server running as a subprocess.
type SubprocessServer struct {
	Name     string
	TempDir  string
	BaseURL  string
	Port     int
	cmd      *exec.Cmd
	logFile  *os.File
	configFile string
}

// SubprocessConfig contains configuration for starting a subprocess server.
type SubprocessConfig struct {
	Name           string
	Mode           string // dev, interop, strict
	ExtraConfig    string // Additional TOML config to append
}

// BuildBinary builds the opencloudmesh-go binary for testing.
// Returns the path to the built binary.
func BuildBinary(t *testing.T) string {
	t.Helper()

	// Build to temp location
	tempDir, err := os.MkdirTemp("", "ocm-build-*")
	if err != nil {
		t.Fatalf("failed to create temp dir for binary: %v", err)
	}

	binaryName := "opencloudmesh-go"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(tempDir, binaryName)

	// Run go build
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/opencloudmesh-go")
	cmd.Dir = findProjectRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build binary: %v\nOutput: %s", err, output)
	}

	// Register cleanup
	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return binaryPath
}

// findProjectRoot finds the project root by looking for go.mod
func findProjectRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find project root (go.mod)")
		}
		dir = parent
	}
}

// StartSubprocessServer starts a server as a subprocess with the given config.
func StartSubprocessServer(t *testing.T, binaryPath string, cfg SubprocessConfig) *SubprocessServer {
	t.Helper()

	// Create temp directory for this server
	tempDir, err := os.MkdirTemp("", "ocm-subprocess-"+cfg.Name+"-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	// Get a free port
	port, err := getFreePort()
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to get free port: %v", err)
	}

	// Create config file
	configPath := filepath.Join(tempDir, "config.toml")
	configContent := generateTOMLConfig(cfg.Name, port, tempDir, cfg.Mode, cfg.ExtraConfig)
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to write config file: %v", err)
	}

	// Create log file
	logPath := filepath.Join(tempDir, "server.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create log file: %v", err)
	}

	// Start subprocess
	cmd := exec.Command(binaryPath, "--config", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = tempDir

	if err := cmd.Start(); err != nil {
		logFile.Close()
		os.RemoveAll(tempDir)
		t.Fatalf("failed to start subprocess: %v", err)
	}

	baseURL := fmt.Sprintf("http://localhost:%d", port)

	srv := &SubprocessServer{
		Name:       cfg.Name,
		TempDir:    tempDir,
		BaseURL:    baseURL,
		Port:       port,
		cmd:        cmd,
		logFile:    logFile,
		configFile: configPath,
	}

	// Wait for server to be ready
	if err := waitForServerReady(baseURL, 10*time.Second); err != nil {
		srv.DumpLogs(t)
		srv.Stop(t)
		t.Fatalf("server %s failed to start: %v", cfg.Name, err)
	}

	t.Logf("Started subprocess server %s at %s (port %d)", cfg.Name, baseURL, port)

	return srv
}

// Stop stops the subprocess server and cleans up resources.
func (s *SubprocessServer) Stop(t *testing.T) {
	t.Helper()

	if s.cmd != nil && s.cmd.Process != nil {
		// Send interrupt signal for graceful shutdown
		s.cmd.Process.Signal(os.Interrupt)

		// Wait with timeout
		done := make(chan error, 1)
		go func() {
			done <- s.cmd.Wait()
		}()

		select {
		case <-done:
			// Process exited
		case <-time.After(5 * time.Second):
			// Force kill
			s.cmd.Process.Kill()
			<-done
		}
	}

	if s.logFile != nil {
		s.logFile.Close()
	}

	if s.TempDir != "" {
		os.RemoveAll(s.TempDir)
	}
}

// DumpLogs outputs the server logs to the test log.
func (s *SubprocessServer) DumpLogs(t *testing.T) {
	t.Helper()

	logPath := filepath.Join(s.TempDir, "server.log")
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Logf("failed to read logs for %s: %v", s.Name, err)
		return
	}

	t.Logf("=== Logs for server %s ===\n%s\n=== End logs ===", s.Name, string(content))
}

// generateTOMLConfig creates a TOML config for a test server.
func generateTOMLConfig(name string, port int, dataDir, mode, extra string) string {
	// Determine SSRF mode based on operating mode
	ssrfMode := "off"
	if mode == "strict" {
		ssrfMode = "block"
	}

	// Top-level keys must come before any [section] headers in TOML
	config := fmt.Sprintf(`mode = "%s"
listen_addr = ":%d"
external_origin = "http://localhost:%d"
external_base_path = ""

[tls]
mode = "off"

[identity]
session_ttl_hours = 24

[server]
trusted_proxies = ["127.0.0.0/8", "::1/128"]

[server.bootstrap_admin]
username = "admin"

[outbound_http]
ssrf_mode = "%s"
timeout_ms = 5000
connect_timeout_ms = 2000
max_redirects = 1
max_response_bytes = 1048576
insecure_skip_verify = true

[signature]
mode = "off"
`, mode, port, port, ssrfMode)

	if extra != "" {
		config += "\n" + extra
	}

	return config
}

// waitForServerReady waits for a server to respond to HTTP requests.
func waitForServerReady(baseURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 1 * time.Second}

	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/api/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("server not ready after %v", timeout)
}

// TwoInstanceHarness manages two subprocess servers for federation testing.
type TwoInstanceHarness struct {
	BinaryPath string
	Server1    *SubprocessServer
	Server2    *SubprocessServer
}

// StartTwoInstances builds and starts two server instances.
func StartTwoInstances(t *testing.T, cfg1, cfg2 SubprocessConfig) *TwoInstanceHarness {
	t.Helper()

	binaryPath := BuildBinary(t)

	server1 := StartSubprocessServer(t, binaryPath, cfg1)
	server2 := StartSubprocessServer(t, binaryPath, cfg2)

	return &TwoInstanceHarness{
		BinaryPath: binaryPath,
		Server1:    server1,
		Server2:    server2,
	}
}

// Stop stops both servers.
func (h *TwoInstanceHarness) Stop(t *testing.T) {
	t.Helper()

	if h.Server1 != nil {
		h.Server1.Stop(t)
	}
	if h.Server2 != nil {
		h.Server2.Stop(t)
	}
}

// DumpLogs outputs logs from both servers.
func (h *TwoInstanceHarness) DumpLogs(t *testing.T) {
	t.Helper()

	if h.Server1 != nil {
		h.Server1.DumpLogs(t)
	}
	if h.Server2 != nil {
		h.Server2.DumpLogs(t)
	}
}
