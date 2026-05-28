// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Package harness provides test utilities for integration tests.
package harness

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// SubprocessServer represents a server running as a subprocess.
type SubprocessServer struct {
	Name       string
	TempDir    string
	BaseURL    string
	Port       int
	cmd        *exec.Cmd
	logFile    *os.File
	configFile string
}

// SubprocessConfig contains configuration for starting a subprocess server.
type SubprocessConfig struct {
	Name                    string
	Mode                    string // dev, compat, strict; legacy alias interop also works
	CompatibilityScope      string
	KeepSignatureDefaults   bool              // when true, skip the [signature] override block so mode presets apply
	SSRFMode                string            // when "strict", emits [outbound_http.ssrf.mode = "strict"] in [outbound_http]
	DisableProxyEnvFallback bool              // when true, emits proxy_env_fallback = false in [outbound_http]
	ExtraConfig             string            // Additional TOML config to append
	ExtraFiles              map[string]string // Extra files to write to tempDir: {relativePath: contents}
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

	// Write extra files before config.toml (so config can reference them)
	for relPath, contents := range cfg.ExtraFiles {
		absPath := filepath.Join(tempDir, relPath)
		// Ensure parent directory exists
		if dir := filepath.Dir(absPath); dir != tempDir {
			if err := os.MkdirAll(dir, 0755); err != nil {
				os.RemoveAll(tempDir)
				t.Fatalf("failed to create directory for extra file %s: %v", relPath, err)
			}
		}
		if err := os.WriteFile(absPath, []byte(contents), 0644); err != nil {
			os.RemoveAll(tempDir)
			t.Fatalf("failed to write extra file %s: %v", relPath, err)
		}
	}

	// Create config file
	configPath := filepath.Join(tempDir, "config.toml")
	configContent := generateTOMLConfig(
		cfg.Name,
		port,
		tempDir,
		cfg.Mode,
		cfg.CompatibilityScope,
		cfg.KeepSignatureDefaults,
		cfg.DisableProxyEnvFallback,
		cfg.ExtraConfig,
	)
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to write config file: %v", err)
	}

	// Derive transport, base URL, and readiness path from the FINAL effective
	// config, not just the preset inputs. ExtraConfig may override TLS (or other
	// transport-relevant settings) after the preset-derived base config is
	// generated, so re-loading the rendered config.toml through the same loader
	// the binary uses (config.Load) is the only reliable source of truth for the
	// scheme the subprocess actually listens with and the path endpoints mount
	// under. See localListenerBaseURL in harness.go for the in-process parallel.
	finalCfg, err := loadEffectiveSubprocessConfig(configPath, tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to load effective config for %s: %v", cfg.Name, err)
	}
	baseURL := localListenerBaseURL(finalCfg.TLS.Mode, port)

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

	srv := &SubprocessServer{
		Name:       cfg.Name,
		TempDir:    tempDir,
		BaseURL:    baseURL,
		Port:       port,
		cmd:        cmd,
		logFile:    logFile,
		configFile: configPath,
	}

	// Wait for server to be ready. App endpoints (including /api/healthz) mount
	// under external_base_path when set, so probe the path the final effective
	// config actually uses rather than assuming root.
	if err := waitForServerReady(healthEndpointURL(baseURL, finalCfg.ExternalBasePath), 10*time.Second); err != nil {
		srv.DumpLogs(t)
		srv.Stop(t)
		t.Fatalf("server %s failed to start: %v", cfg.Name, err)
	}

	t.Logf("Started subprocess server %s at %s (port %d)", cfg.Name, baseURL, port)

	return srv
}

// Client returns an HTTP client appropriate for this server's transport.
// For HTTPS servers with a self-signed certificate, the returned client skips
// TLS verification -- this is intentional and test-only.
func (s *SubprocessServer) Client() *http.Client {
	if strings.HasPrefix(s.BaseURL, "https://") {
		return newInsecureHTTPSClient(30 * time.Second)
	}
	return &http.Client{Timeout: 30 * time.Second}
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

// subprocessChdirMu serializes the working-directory switch used while loading
// a subprocess config. The integration tests run serially (no t.Parallel), but
// os.Chdir is process-global, so this guards against concurrent harness callers
// corrupting each other's view of the working directory.
var subprocessChdirMu sync.Mutex

// loadEffectiveSubprocessConfig loads the fully rendered config from the written
// config.toml using the same loader the binary uses (config.Load). The binary
// runs with its working directory set to dataDir (cmd.Dir == tempDir), so any
// relative paths in the config (for example peer_trust config_paths or outbound
// TLS CA paths) resolve against dataDir. We temporarily switch to dataDir while
// loading so the harness derives the identical effective config -- including the
// final TLS mode and external base path -- that the running subprocess uses.
func loadEffectiveSubprocessConfig(configPath, dataDir string) (*config.Config, error) {
	subprocessChdirMu.Lock()
	defer subprocessChdirMu.Unlock()

	prevDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get working directory: %w", err)
	}
	if err := os.Chdir(dataDir); err != nil {
		return nil, fmt.Errorf("chdir to data dir %s: %w", dataDir, err)
	}
	defer func() { _ = os.Chdir(prevDir) }()

	return config.Load(config.LoaderOptions{ConfigPath: configPath})
}

// needsSecureTransport reports whether the mode+scope combination requires HTTPS.
// The config loader rejects tls.mode=off for compatibility_scope "none" and "scoped".
// An empty scope with strict (or default-empty) mode implies "none" via the preset.
func needsSecureTransport(mode, compatibilityScope string) bool {
	scope := strings.ToLower(strings.TrimSpace(compatibilityScope))
	switch scope {
	case "none", "scoped":
		return true
	case "":
		m := strings.ToLower(strings.TrimSpace(mode))
		return m == "strict" || m == ""
	}
	return false
}

// extraTLSMode scans ExtraConfig for a [tls] table and returns the tls.mode it
// declares. hasTLSTable reports whether ExtraConfig defines a [tls] table at all
// (even when it omits an explicit mode key); mode is the value of the mode key
// inside that table, or "" when the table omits it. This is a deliberately
// small TOML peek: it only tracks table headers and a single mode = "..." line
// so generateTOMLConfig can keep the preset-derived [tls] block and the
// generated default public_origin consistent with a test's TLS override.
func extraTLSMode(extra string) (mode string, hasTLSTable bool) {
	inTLS := false
	for _, line := range strings.Split(extra, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inTLS = trimmed == "[tls]"
			if inTLS {
				hasTLSTable = true
			}
			continue
		}
		if inTLS {
			if key, value, ok := strings.Cut(trimmed, "="); ok && strings.TrimSpace(key) == "mode" {
				mode = strings.Trim(strings.TrimSpace(value), `"'`)
			}
		}
	}
	return mode, hasTLSTable
}

// extraDefinesTLSTable reports whether ExtraConfig declares its own [tls] table.
// When it does, generateTOMLConfig omits the preset-derived [tls] block so the
// test can override the listener transport without a duplicate-table TOML error.
func extraDefinesTLSTable(extra string) bool {
	_, hasTLSTable := extraTLSMode(extra)
	return hasTLSTable
}

// extraDefinesPublicOrigin reports whether ExtraConfig sets the top-level
// public_origin key. When it does, generateTOMLConfig omits its generated
// default so the test's explicit origin wins (and so the rendered TOML does not
// carry a duplicate public_origin key). Only root-table assignments count;
// keys inside a [table] are ignored.
func extraDefinesPublicOrigin(extra string) bool {
	inRootTable := true
	for _, line := range strings.Split(extra, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inRootTable = false
			continue
		}
		if !inRootTable {
			continue
		}
		if key, _, ok := strings.Cut(trimmed, "="); ok && strings.TrimSpace(key) == "public_origin" {
			return true
		}
	}
	return false
}

// generateTOMLConfig creates a TOML config for a test server.
// Uses the new Reva-aligned TOML shape. The mode preset (dev/compat/strict)
// drives defaults via config.Load(), including token exchange settings.
// When keepSigDefaults is false, signature mode is forced off for test simplicity.
// When true, the [signature] block is omitted so the mode preset's defaults apply.
//
// For strict/scoped-like configurations (CompatibilityScope "none" or "scoped"),
// the generated config uses HTTPS with a self-signed certificate instead of
// plain HTTP, matching the transport requirements enforced by the loader.
//
// Per-service configuration ([http.services.*]) is NOT included in the base
// config to avoid TOML key conflicts when tests provide ExtraConfig with
// per-service overrides. Services derive cross-cutting defaults from SharedDeps
// at construction time, so the base config can stay minimal.
func generateTOMLConfig(name string, port int, dataDir, mode, compatibilityScope string, keepSigDefaults bool, disableProxyEnvFallback bool, extra string) string {
	secure := needsSecureTransport(mode, compatibilityScope)

	// Derive the scheme for the generated default public_origin from the FINAL
	// effective TLS mode, not just the preset heuristic. ExtraConfig may override
	// the preset transport via its own [tls] table; when it sets an explicit mode
	// the generated default origin must follow that override, because discovery
	// (internal/services/wellknown) advertises endpoints from public_origin and
	// would otherwise advertise the wrong scheme. Any tls.mode other than "off"
	// implies HTTPS, matching localListenerScheme.
	publicOriginSecure := secure
	if overrideMode, _ := extraTLSMode(extra); strings.TrimSpace(overrideMode) != "" {
		publicOriginSecure = localListenerScheme(overrideMode) == "https"
	}

	var publicOrigin string
	if publicOriginSecure {
		publicOrigin = fmt.Sprintf("https://localhost:%d", port)
	} else {
		publicOrigin = fmt.Sprintf("http://localhost:%d", port)
	}

	// Omit the generated public_origin when the test sets its own so the explicit
	// value wins and the rendered TOML stays free of duplicate keys.
	publicOriginLine := ""
	if !extraDefinesPublicOrigin(extra) {
		publicOriginLine = fmt.Sprintf("public_origin = %q\n", publicOrigin)
	}

	config := fmt.Sprintf(`# Generated config for test server: %s
mode = "%s"
listen_addr = ":%d"
%sexternal_base_path = ""

`, name, mode, port, publicOriginLine)

	if compatibilityScope != "" {
		config += fmt.Sprintf("compatibility_scope = %q\n\n", compatibilityScope)
	}

	// Emit the preset-derived [tls] block unless the test supplies its own [tls]
	// table in ExtraConfig. TOML rejects a duplicate [tls] table, so when the
	// extra config defines one we omit ours and let the test's TLS settings
	// drive the final effective transport. The harness derives BaseURL and the
	// readiness scheme from that final config, so an overriding [tls] is honored.
	if !extraDefinesTLSTable(extra) {
		if secure {
			// selfsigned TLS; self_signed_dir defaults to ".ocm/certs" relative
			// to the process working directory (tempDir).
			config += `[tls]
mode = "selfsigned"

`
		} else {
			config += `[tls]
mode = "off"

`
		}
	}

	if secure {
		// insecure_skip_verify must be false for scoped/none scope guardrails to pass.
		config += `[server]
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
	} else {
		config += `[server]
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
	}

	if disableProxyEnvFallback {
		config += "proxy_env_fallback = false\n"
	}

	if !keepSigDefaults {
		config += `
[signature]
inbound_mode = "off"
outbound_mode = "off"
`
	}

	if extra != "" {
		config += "\n# Extra config appended by test\n" + extra
	}

	return config
}

// newInsecureHTTPSClient returns an http.Client that skips TLS verification.
// It clones http.DefaultTransport when possible so connection pooling and other
// defaults are preserved; falls back to a fresh Transport when DefaultTransport
// has been replaced with a non-*http.Transport. Use only for test-only
// self-signed certificate probing.
//
//nolint:gosec // InsecureSkipVerify is intentional for test-only self-signed cert probing.
func newInsecureHTTPSClient(timeout time.Duration) *http.Client {
	var transport *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = base.Clone()
	} else {
		transport = &http.Transport{}
	}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// healthEndpointURL builds the readiness probe URL for a server. App endpoints
// (including /api/healthz) are mounted under externalBasePath when it is set
// (see internal/platform/http/server/routes.go), so the probe must include it.
// An empty externalBasePath yields the root-mounted /api/healthz.
func healthEndpointURL(baseURL, externalBasePath string) string {
	base := strings.TrimSuffix(baseURL, "/")
	bp := strings.Trim(externalBasePath, "/")
	if bp == "" {
		return base + "/api/healthz"
	}
	return base + "/" + bp + "/api/healthz"
}

// waitForServerReady waits for a server to respond at healthURL.
// For HTTPS URLs (self-signed TLS), uses an insecure client for the
// readiness probe only -- the server config itself still enforces strict TLS.
func waitForServerReady(healthURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	var client *http.Client
	if strings.HasPrefix(healthURL, "https://") {
		client = newInsecureHTTPSClient(1 * time.Second)
	} else {
		client = &http.Client{Timeout: 1 * time.Second}
	}

	for time.Now().Before(deadline) {
		resp, err := client.Get(healthURL)
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
