package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_ProxyURL_ValidValues(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL string
	}{
		{"standard http proxy", "http://mitm:8080"},
		{"https proxy", "https://proxy.example.com:3128"},
		{"ip proxy", "http://192.168.1.1:8080"},
		{"loopback allowed", "http://127.0.0.1:8080"},
		{"private loopback name", "http://mitm.local:8080"},
		{"no path", "http://proxy.example.com"},
		{"empty no proxy", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `mode = "strict"
`
			if tt.proxyURL != "" {
				tomlContent += `
[outbound_http]
proxy_url = "` + tt.proxyURL + `"
`
			}
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			cfg, err := Load(LoaderOptions{ConfigPath: configPath})
			if err != nil {
				t.Fatalf("Load() unexpected error for proxy_url %q: %v", tt.proxyURL, err)
			}
			if cfg.OutboundHTTP.ProxyURL != tt.proxyURL {
				t.Errorf("expected ProxyURL %q, got %q", tt.proxyURL, cfg.OutboundHTTP.ProxyURL)
			}
		})
	}
}

func TestLoad_ProxyURL_InvalidValues(t *testing.T) {
	tests := []struct {
		name      string
		proxyURL  string
		wantInErr string
	}{
		{
			name:      "ftp scheme",
			proxyURL:  "ftp://proxy.example.com:21",
			wantInErr: "proxy_url",
		},
		{
			name:      "userinfo present",
			proxyURL:  "http://user:pass@proxy.example.com:8080",
			wantInErr: "proxy_url",
		},
		{
			name:      "empty host with port",
			proxyURL:  "http://:8080",
			wantInErr: "proxy_url",
		},
		{
			name:      "no scheme",
			proxyURL:  "proxy.example.com:8080",
			wantInErr: "proxy_url",
		},
		{
			name:      "username only no password",
			proxyURL:  "http://user@proxy.example.com:8080",
			wantInErr: "proxy_url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `mode = "strict"

[outbound_http]
proxy_url = "` + tt.proxyURL + `"
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatalf("Load() expected error for proxy_url %q, got nil", tt.proxyURL)
			}
			if !strings.Contains(err.Error(), tt.wantInErr) {
				t.Errorf("expected error to contain %q, got: %v", tt.wantInErr, err)
			}
		})
	}
}

func TestLoad_ProxyURL_StrictModeAllowsLoopback(t *testing.T) {
	// Under compatibility_scope=none the proxy host is operator-trusted;
	// loopback and private addresses must be accepted for proxy_url.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `mode = "strict"

[outbound_http]
proxy_url = "http://127.0.0.1:8080"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v (loopback must be allowed for proxy under compatibility_scope=none)", err)
	}
	if cfg.OutboundHTTP.ProxyURL != "http://127.0.0.1:8080" {
		t.Errorf("expected ProxyURL http://127.0.0.1:8080, got %q", cfg.OutboundHTTP.ProxyURL)
	}
}

func TestLoad_ProxyURL_DefaultEmpty(t *testing.T) {
	// No proxy_url in config or flags; field must default to empty string.
	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OutboundHTTP.ProxyURL != "" {
		t.Errorf("expected ProxyURL empty by default, got %q", cfg.OutboundHTTP.ProxyURL)
	}
}

func TestProxyEnvFallback_StrictPresetDefaultTrue(t *testing.T) {
	cfg := StrictConfig()
	if !cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("strict preset must default proxy_env_fallback=true")
	}
}

func TestProxyEnvFallback_CompatPresetDefaultTrue(t *testing.T) {
	cfg := CompatConfig()
	if !cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("compat preset must default proxy_env_fallback=true")
	}
}

func TestProxyEnvFallback_DevPresetDefaultFalse(t *testing.T) {
	cfg := DevConfig()
	if cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("dev preset must default proxy_env_fallback=false")
	}
}

func TestProxyEnvFallback_ExplicitTOMLTrueOverridesDevPreset(t *testing.T) {
	// dev preset defaults proxy_env_fallback=false; explicit true in TOML must override it.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "dev"

[outbound_http]
proxy_env_fallback = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("explicit proxy_env_fallback=true in TOML must override the dev preset default (false)")
	}
}

func TestProxyEnvFallback_ExplicitTOMLFalse(t *testing.T) {
	// strict preset defaults true; explicit false in TOML must override it.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"

[outbound_http]
proxy_env_fallback = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("explicit proxy_env_fallback=false in TOML must override the strict preset default")
	}
}

func TestProxyEnvFallback_OmittedTOMLPreservesPreset(t *testing.T) {
	// [outbound_http] section present but proxy_env_fallback not set;
	// the strict preset value (true) must be preserved.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"

[outbound_http]
timeout_ms = 8000
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("omitted proxy_env_fallback in TOML must preserve the strict preset default (true)")
	}
}

func TestProxyEnvFallback_ProxyURLPrecedence(t *testing.T) {
	// When proxy_url is set alongside proxy_env_fallback=true, both fields
	// may coexist in the config contract; proxy_url takes precedence at the
	// HTTP client level (env vars are not consulted when an explicit URL is set).
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"

[outbound_http]
proxy_url = "http://explicit.proxy:8080"
proxy_env_fallback = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OutboundHTTP.ProxyURL != "http://explicit.proxy:8080" {
		t.Errorf("expected ProxyURL http://explicit.proxy:8080, got %q", cfg.OutboundHTTP.ProxyURL)
	}
	if !cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("proxy_env_fallback should remain true when proxy_url is also set")
	}
}

func TestOutboundHTTPConfigStrict_ProxyEnvFallbackFalse(t *testing.T) {
	// OutboundHTTPConfigStrict is a non-ambient building block: it must never
	// enable environment-based proxy discovery on its own.  StrictConfig() may
	// layer proxy_env_fallback=true on top, but the raw builder must stay false
	// so callers that use it directly get a safe, non-ambient default.
	cfg := OutboundHTTPConfigStrict()
	if cfg.ProxyEnvFallback {
		t.Error("OutboundHTTPConfigStrict() must return ProxyEnvFallback=false (non-ambient by default)")
	}
}
