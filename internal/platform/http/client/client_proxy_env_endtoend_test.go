package client_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// clearProxyEnvVars clears all proxy-related env vars so ambient values cannot
// leak into the test. t.Setenv restores prior values on test cleanup.
//
// REQUEST_METHOD is cleared because golang.org/x/net/http/httpproxy.FromEnvironment
// (used by buildProxyFunc when use_env_fallback is true) treats a non-empty
// REQUEST_METHOD as a CGI environment and returns a no-proxy config, which
// would silently disable the env proxy the test sets up. Clearing it keeps the
// env-proxy path hermetic against ambient CGI-style env leakage from the
// test runner.
func clearProxyEnvVars(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
		"http_proxy", "https_proxy", "no_proxy", "all_proxy",
		"REQUEST_METHOD",
	} {
		t.Setenv(key, "")
	}
}

// TestClient_EnvOverrideEndToEnd_UseEnvFallbackTrue covers the full env ->
// config.Load -> client.New -> proxy routing path when the operator opts in to
// env-based proxy discovery via OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK=true.
//
// The env override flips cfg.OutboundHTTP.UseEnvFallback to true at load time,
// and client.New then snapshots HTTP_PROXY at construction time so requests
// route through the env proxy.
func TestClient_EnvOverrideEndToEnd_UseEnvFallbackTrue(t *testing.T) {
	var proxyHit atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit.Store(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("via-env-proxy"))
	}))
	defer proxy.Close()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	// dev mode keeps SSRF off so the preflight check does not block the
	// TEST-NET-3 destination used below.
	if err := os.WriteFile(configPath, []byte("mode = \"dev\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Env override opts in to env-based proxy discovery.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "true")
	// Set HTTP_PROXY before constructing the client so buildProxyFunc snapshots
	// it at New() time. Clear the other proxy vars so ambient values do not
	// interfere.
	clearProxyEnvVars(t)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)

	cfg, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.OutboundHTTP.UseEnvFallback {
		t.Fatal("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK=true must set UseEnvFallback=true")
	}

	c := httpclient.New(&cfg.OutboundHTTP, nil)

	// 203.0.113.10 is TEST-NET-3; not private/loopback so dev-mode SSRF (off)
	// does not block it, and the env proxy is reachable so the request succeeds.
	resp, err := c.Get(context.Background(), "http://203.0.113.10/api")
	if err != nil {
		t.Fatalf("expected success through env proxy, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if !proxyHit.Load() {
		t.Error("request did not route through the env proxy")
	}
}

// TestClient_EnvOverrideEndToEnd_DefaultFalseDirect covers the reverse path:
// with no env override (default false), config.Load keeps UseEnvFallback=false
// and client.New ignores HTTP_PROXY, connecting directly to the destination.
//
// The destination must run on a non-loopback IP. Go's httpproxy unconditionally
// bypasses proxies for loopback destinations (127.x and ::1) regardless of env
// configuration, so a loopback destination would let a regression that always
// honors the env proxy pass this test: the proxy would be bypassed either way.
// A non-loopback destination plus a hit-counting proxy server makes the
// invariant observable: with the default (use_env_fallback=false) the proxy
// must never be contacted, and the request must reach the destination directly.
func TestClient_EnvOverrideEndToEnd_DefaultFalseDirect(t *testing.T) {
	localIP := findNonLoopbackIPv4()
	if localIP == nil {
		t.Skip("no non-loopback IPv4 interface available; skipping default-false direct test")
	}

	var proxyHit atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit.Store(true)
		t.Errorf("proxy must not be contacted when use_env_fallback is false: got %s %s",
			r.Method, r.RequestURI)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()

	// Destination server on a non-loopback IP so Go's httpproxy does not
	// special-case it independently of use_env_fallback.
	destListener, err := net.Listen("tcp", localIP.String()+":0")
	if err != nil {
		t.Fatalf("listen on non-loopback IP %s: %v", localIP, err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("direct"))
	}))
	server.Listener = destListener
	server.Start()
	defer server.Close()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte("mode = \"dev\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Clear the env override so the dev preset default (false) wins.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	// Point HTTP_PROXY at a real test server. With use_env_fallback=false the
	// env proxy must be ignored entirely; if a regression honored it, the
	// request would route through proxyHit and fail the assertion below.
	clearProxyEnvVars(t)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)

	cfg, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OutboundHTTP.UseEnvFallback {
		t.Fatal("default must keep UseEnvFallback=false")
	}

	c := httpclient.New(&cfg.OutboundHTTP, nil)

	// Direct connection to the non-loopback destination must succeed; the env
	// proxy is ignored because UseEnvFallback is false.
	resp, err := c.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("expected direct connection, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if proxyHit.Load() {
		t.Error("env proxy must not be contacted when use_env_fallback is false")
	}
}
