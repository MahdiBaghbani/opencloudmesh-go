// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package harness

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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

// needsSecureTransport reports whether the mode requires HTTPS listener transport.
func needsSecureTransport(mode string) bool {
	m := strings.ToLower(strings.TrimSpace(mode))
	return m == "strict" || m == ""
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

// extraDefinesPersistenceTable reports whether ExtraConfig declares its own
// [persistence] table. When it does, generateTOMLConfig omits the generated
// memory-backend pin so the test can pick a durable backend without a
// duplicate-table TOML error.
func extraDefinesPersistenceTable(extra string) bool {
	for _, line := range strings.Split(extra, "\n") {
		if strings.TrimSpace(line) == "[persistence]" {
			return true
		}
	}

	return false
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
// Uses the Reva-aligned TOML shape. The mode preset (dev/strict)
// drives defaults via config.Load(), including token exchange settings.
//
// For strict mode configurations, the generated config uses HTTPS with a
// self-signed certificate instead of plain HTTP, matching the transport
// requirements enforced by the loader.
//
// Per-service configuration ([http.services.*]) is NOT included in the base
// config to avoid TOML key conflicts when tests provide ExtraConfig with
// per-service overrides. Services derive cross-cutting defaults from SharedDeps
// at construction time, so the base config can stay minimal.
func generateTOMLConfig(name string, port int, _, mode string, disableUseEnvFallback bool, tlsRootCAFile, bootstrapAdminPassword, publicOriginHost string, extra string) string {
	secure := needsSecureTransport(mode)
	// Capture before the local config string shadows the config package.
	memoryBackend := config.BackendMemory

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

	originHost := "localhost"
	if strings.TrimSpace(publicOriginHost) != "" {
		originHost = strings.TrimSpace(publicOriginHost)
	}

	if publicOriginSecure {
		publicOrigin = "https://" + net.JoinHostPort(strings.Trim(originHost, "[]"), strconv.Itoa(port))
	} else {
		publicOrigin = "http://" + net.JoinHostPort(strings.Trim(originHost, "[]"), strconv.Itoa(port))
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

	// Root-level ExtraConfig keys must appear before any [table]. Appending
	// them after [outbound_http] would bind them to that table in TOML.
	rootExtra, tableExtra := splitExtraConfigRootKeys(extra)
	if rootExtra != "" {
		config += rootExtra + "\n"
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

	// Pin the memory backend explicitly: it boots fast and keeps generated
	// configs free of on-disk state. The pure-Go sqlite driver works in the
	// CGO_ENABLED=0 subprocess binary, so tests that need durable persistence
	// declare their own [persistence] table in ExtraConfig.
	if !extraDefinesPersistenceTable(extra) {
		config += fmt.Sprintf(`[persistence]
backend = %q

`, memoryBackend)
	}

	bootstrapAdmin := "[server.bootstrap_admin]\nusername = \"admin\"\n"
	if strings.TrimSpace(bootstrapAdminPassword) != "" {
		bootstrapAdmin += fmt.Sprintf("password = %q\n", bootstrapAdminPassword)
	}

	bootstrapAdmin += "\n"

	if secure {
		// insecure_skip_verify must be false for strict mode guardrails to pass.
		config += `[server]
trusted_proxies = ["127.0.0.0/8", "::1/128"]

` + bootstrapAdmin + `[outbound_http]
timeout_ms = 5000
connect_timeout_ms = 2000
max_redirects = 1
max_response_bytes = 1048576
insecure_skip_verify = false
`
	} else {
		config += `[server]
trusted_proxies = ["127.0.0.0/8", "::1/128"]

` + bootstrapAdmin + `[outbound_http]
timeout_ms = 5000
connect_timeout_ms = 2000
max_redirects = 1
max_response_bytes = 1048576
insecure_skip_verify = true
`
	}

	if disableUseEnvFallback {
		config += "use_env_fallback = false\n"
	}

	if strings.TrimSpace(tlsRootCAFile) != "" {
		config += fmt.Sprintf("tls_root_ca_file = %q\n", tlsRootCAFile)
	}

	if tableExtra != "" {
		config += "\n# Extra config appended by test\n" + tableExtra
	}

	return config
}

// splitExtraConfigRootKeys separates leading root key/value lines from table
// overrides in ExtraConfig. Comments and blank lines before the first [table]
// stay with the root block.
func splitExtraConfigRootKeys(extra string) (root string, tables string) {
	extra = strings.TrimSpace(extra)
	if extra == "" {
		return "", ""
	}

	lines := strings.Split(extra, "\n")
	rootLines := make([]string, 0, len(lines))
	tableStart := -1

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			rootLines = append(rootLines, line)
			continue
		}

		if strings.HasPrefix(trimmed, "[") {
			tableStart = i
			break
		}

		rootLines = append(rootLines, line)
	}

	if tableStart < 0 {
		return strings.TrimSpace(strings.Join(rootLines, "\n")), ""
	}

	// Drop trailing blank/comment-only padding from the root block.
	for len(rootLines) > 0 {
		trimmed := strings.TrimSpace(rootLines[len(rootLines)-1])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			rootLines = rootLines[:len(rootLines)-1]
			continue
		}

		break
	}

	return strings.TrimSpace(strings.Join(rootLines, "\n")), strings.TrimSpace(strings.Join(lines[tableStart:], "\n"))
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
func waitForServerReady(ctx context.Context, healthURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	var client *http.Client
	if strings.HasPrefix(healthURL, "https://") {
		client = newInsecureHTTPSClient(1 * time.Second)
	} else {
		client = &http.Client{Timeout: 1 * time.Second}
	}

	for time.Now().Before(deadline) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if reqErr != nil {
			return fmt.Errorf("build readiness probe request: %w", reqErr)
		}

		resp, err := client.Do(req)
		if err == nil {
			//nolint:errcheck // test cleanup: response body close
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
