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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

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
