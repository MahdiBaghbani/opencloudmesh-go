// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package harness

import (
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
	Name                   string
	Mode                   string            // dev or strict
	Port                   int               // when non-zero, binds listen_addr to this port
	DisableUseEnvFallback  bool              // when true, emits use_env_fallback = false in [outbound_http]
	TLSRootCAFile          string            // when set, adds tls_root_ca_file under [outbound_http]
	BootstrapAdminPassword string            // when set, adds password under [server.bootstrap_admin]
	PublicOriginHost       string            // when set, overrides localhost in generated public_origin
	ExtraConfig            string            // Additional TOML config to append
	ExtraFiles             map[string]string // Extra files to write to tempDir: {relativePath: contents}
}

// BuildBinary builds the opencloudmesh-go binary for testing.
// Returns the path to the built binary.
func BuildBinary(t *testing.T) string {
	t.Helper()

	// Build to temp location
	tempDir := t.TempDir()

	binaryName := "opencloudmesh-go"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}

	binaryPath := filepath.Join(tempDir, binaryName)

	// Run go build
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", binaryPath, "./cmd/opencloudmesh-go") //nolint:gosec // test harness: intentional subprocess launch with test-controlled args
	cmd.Dir = findProjectRoot(t)

	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build binary: %v\nOutput: %s", err, output)
	}

	return binaryPath
}

// findProjectRoot finds the project root by looking for go.mod
func findProjectRoot(t *testing.T) string {
	t.Helper()
	return FindProjectRoot(t)
}

// FindProjectRoot finds the project root by looking for go.mod.
func FindProjectRoot(t *testing.T) string {
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
	tempDir := t.TempDir()

	// Get a free port unless the caller reserved one (strict pair fixtures).
	port := cfg.Port
	if port == 0 {
		var portErr error

		port, portErr = getFreePort(t.Context())
		if portErr != nil {
			t.Fatalf("failed to get free port: %v", portErr)
		}
	}

	// Write extra files before config.toml (so config can reference them)
	for relPath, contents := range cfg.ExtraFiles {
		absPath := filepath.Join(tempDir, relPath)
		// Ensure parent directory exists
		if dir := filepath.Dir(absPath); dir != tempDir {
			if mkdirErr := os.MkdirAll(dir, 0755); mkdirErr != nil { //nolint:gosec // test fixture: 0755 on a local controlled test temp dir, not an attacker-controlled production path
				t.Fatalf("failed to create directory for extra file %s: %v", relPath, mkdirErr)
			}
		}

		if writeErr := os.WriteFile(absPath, []byte(contents), 0644); writeErr != nil {
			t.Fatalf("failed to write extra file %s: %v", relPath, writeErr)
		}
	}

	// Create config file
	configPath := filepath.Join(tempDir, "config.toml")

	configContent := generateTOMLConfig(
		cfg.Name,
		port,
		tempDir,
		cfg.Mode,
		cfg.DisableUseEnvFallback,
		cfg.TLSRootCAFile,
		cfg.BootstrapAdminPassword,
		cfg.PublicOriginHost,
		cfg.ExtraConfig,
	)
	if writeErr := os.WriteFile(configPath, []byte(configContent), 0644); writeErr != nil {
		t.Fatalf("failed to write config file: %v", writeErr)
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
		t.Fatalf("failed to load effective config for %s: %v", cfg.Name, err)
	}

	baseURL := localListenerBaseURL(finalCfg.TLS.Mode, port)

	// Create log file
	logPath := filepath.Join(tempDir, "server.log")

	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("failed to create log file: %v", err)
	}

	// Start subprocess. t.Context is a backstop kill only: Stop stays the
	// graceful shutdown path because deferred Stop calls run before the test
	// context is canceled.
	cmd := exec.CommandContext(t.Context(), binaryPath, "--config", configPath) //nolint:gosec // test harness: intentional subprocess launch with test-controlled args
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = tempDir
	// Scrub OCM_CONFIG_* env vars that would override the rendered config at
	// runtime and break the hermetic intent of the subprocess. The harness
	// renders every behavior-relevant knob into config.toml; an ambient env
	// override leaking from the test runner's environment could change the
	// subprocess's effective config (for example OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK
	// flipping the env-proxy fallback the test did not ask for). All other env
	// vars (PATH, HOME, etc.) are inherited unchanged so the binary still runs.
	cmd.Env = scrubSubprocessEnv(os.Environ())

	if err := cmd.Start(); err != nil {
		//nolint:errcheck // test cleanup: log file close
		logFile.Close()
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
	if err := waitForServerReady(t.Context(), healthEndpointURL(baseURL, finalCfg.ExternalBasePath), 10*time.Second); err != nil {
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
		//nolint:errcheck // test cleanup: subprocess shutdown
		s.cmd.Process.Signal(os.Interrupt)

		// Wait with timeout
		done := make(chan error, 1)
		go func() {
			done <- s.cmd.Wait()
		}()

		select {
		case <-done:
			// Process exited
		case <-time.After(config.DefaultTestShutdownWait):
			// Force kill
			//nolint:errcheck // test cleanup: subprocess shutdown
			s.cmd.Process.Kill()
			<-done
		}
	}

	if s.logFile != nil {
		//nolint:errcheck // test cleanup: log file close
		s.logFile.Close()
	}

	if s.TempDir != "" {
		//nolint:errcheck // test cleanup: best-effort temp dir removal
		os.RemoveAll(s.TempDir)
	}
}

// syncLog flushes the shared server.log file so reads observe stdout/stderr
// redirected from the subprocess.
func (s *SubprocessServer) syncLog() {
	if s.logFile != nil {
		//nolint:errcheck // test helper: best-effort log sync before read
		_ = s.logFile.Sync()
	}
}

// ReadLog returns the current server.log contents after syncing the shared log
// file. stdout and stderr are redirected to the same file.
func (s *SubprocessServer) ReadLog(t *testing.T) string {
	t.Helper()

	s.syncLog()

	logPath := filepath.Join(s.TempDir, "server.log")

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read logs for %s: %v", s.Name, err)
	}

	return string(content)
}

// LogContainsAny reports whether server.log contains any of the needles after
// syncing the shared log file.
func (s *SubprocessServer) LogContainsAny(needles ...string) bool {
	s.syncLog()

	logPath := filepath.Join(s.TempDir, "server.log")

	content, err := os.ReadFile(logPath)
	if err != nil {
		return false
	}

	logText := string(content)
	for _, needle := range needles {
		if needle != "" && strings.Contains(logText, needle) {
			return true
		}
	}

	return false
}

// DumpLogs outputs the server logs to the test log.
func (s *SubprocessServer) DumpLogs(t *testing.T) {
	t.Helper()

	s.syncLog()

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
//
// The load is hermetic against ambient OCM_CONFIG_* environment overrides: the
// same hermeticEnvBlocklist entries the child-side scrubSubprocessEnv strips
// from the subprocess env are temporarily unset in the parent process for the
// duration of config.Load, so the parent derives the effective config solely
// from the rendered config.toml and the mode preset. This matters because
// applyEnvOverrides reads os.Getenv directly, so an ambient
// OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK (or any future OCM_CONFIG_* knob
// added to the blocklist) set by the test runner could otherwise flip the
// parent's view of the subprocess's effective config and break the harness's
// rendered config.toml contract.
func loadEffectiveSubprocessConfig(configPath, dataDir string) (*config.Config, error) {
	subprocessChdirMu.Lock()
	defer subprocessChdirMu.Unlock()

	restoreEnv := scrubParentConfigEnv()
	defer restoreEnv()

	prevDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get working directory: %w", err)
	}

	if err := os.Chdir(dataDir); err != nil {
		return nil, fmt.Errorf("chdir to data dir %s: %w", dataDir, err)
	}
	//nolint:errcheck // test cleanup: restore working directory
	defer func() { _ = os.Chdir(prevDir) }()

	return config.Load(config.LoaderOptions{ConfigPath: configPath})
}

// scrubParentConfigEnv temporarily unsets every OCM_CONFIG_* environment
// variable in the current process that the harness blocklists, so a parent-side
// config.Load cannot be influenced by ambient test-runner values. It returns a
// restore function that re-applies the prior values. Callers must hold
// subprocessChdirMu while scrubbing and restoring so concurrent harness callers
// do not race on the process environment; the harness runs serially, but
// os.Setenv/Unsetenv are process-global and shared with the chdir guard.
//
// The parent scrub uses the same hermeticEnvBlocklist as the child-side
// scrubSubprocessEnv so the two stay in sync: any OCM_CONFIG_* knob added to
// the blocklist is scrubbed from both the parent load and the child env.
func scrubParentConfigEnv() func() {
	block := make(map[string]struct{}, len(hermeticEnvBlocklist))
	for _, k := range hermeticEnvBlocklist {
		block[k] = struct{}{}
	}

	var saved []string

	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}

		if _, drop := block[key]; drop {
			saved = append(saved, kv)
			//nolint:errcheck // test env scrub: restore is best-effort
			_ = os.Unsetenv(key)
		}
	}

	return func() {
		for _, kv := range saved {
			key, value, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}

			//nolint:errcheck // test env scrub: restore is best-effort
			_ = os.Setenv(key, value)
		}
	}
}

// hermeticEnvBlocklist is the set of OCM_CONFIG_* environment variables that
// must not leak from the test runner into a hermetic subprocess. Each entry
// overrides a config knob at runtime via applyEnvOverrides, so an ambient value
// could silently change the subprocess's effective config and break the
// harness's rendered config.toml contract.
var hermeticEnvBlocklist = []string{
	config.EnvOutboundHTTPUseEnvFallback,
}

// scrubSubprocessEnv returns env with the hermetic blocklist entries removed.
// It preserves all other environment variables (PATH, HOME, etc.) so the binary
// still runs. Both "KEY=VALUE" and bare "KEY" forms are stripped.
func scrubSubprocessEnv(env []string) []string {
	block := make(map[string]struct{}, len(hermeticEnvBlocklist))
	for _, k := range hermeticEnvBlocklist {
		block[k] = struct{}{}
	}

	scrubbed := make([]string, 0, len(env))
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		if _, drop := block[key]; drop {
			continue
		}

		scrubbed = append(scrubbed, kv)
	}

	return scrubbed
}
