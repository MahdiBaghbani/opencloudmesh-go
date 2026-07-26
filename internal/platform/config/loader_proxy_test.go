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
			// Clear ambient env override so proxy_url tests are deterministic.
			t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
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
			// Clear ambient env override so proxy_url validation tests are deterministic.
			t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
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
	// The proxy host is operator-trusted; loopback must be allowed.
	// loopback and private addresses must be accepted for proxy_url.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
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
		t.Fatalf("Load() error = %v (loopback must be allowed for proxy)", err)
	}
	if cfg.OutboundHTTP.ProxyURL != "http://127.0.0.1:8080" {
		t.Errorf("expected ProxyURL http://127.0.0.1:8080, got %q", cfg.OutboundHTTP.ProxyURL)
	}
}

func TestLoad_ProxyURL_DefaultEmpty(t *testing.T) {
	// No proxy_url in config or flags; field must default to empty string.
	// Clear ambient env override so the default is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OutboundHTTP.ProxyURL != "" {
		t.Errorf("expected ProxyURL empty by default, got %q", cfg.OutboundHTTP.ProxyURL)
	}
}

func TestUseEnvFallback_StrictPresetDefaultFalse(t *testing.T) {
	cfg := StrictConfig()
	if cfg.OutboundHTTP.UseEnvFallback {
		t.Error("strict preset must default use_env_fallback=false")
	}
}

func TestUseEnvFallback_DevPresetDefaultFalse(t *testing.T) {
	cfg := DevConfig()
	if cfg.OutboundHTTP.UseEnvFallback {
		t.Error("dev preset must default use_env_fallback=false")
	}
}

func TestUseEnvFallback_ExplicitTOMLTrueOverridesDevPreset(t *testing.T) {
	// dev preset defaults use_env_fallback=false; explicit true in TOML must opt in.
	// Clear ambient env override so the TOML opt-in is not silently flipped.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "dev"

[outbound_http]
use_env_fallback = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.OutboundHTTP.UseEnvFallback {
		t.Error("explicit use_env_fallback=true in TOML must opt in from the dev preset default (false)")
	}
}

func TestUseEnvFallback_ExplicitTOMLFalse(t *testing.T) {
	// strict preset defaults false; explicit false in TOML keeps it disabled.
	// Clear ambient env override so the TOML opt-out is not silently flipped.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"

[outbound_http]
use_env_fallback = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OutboundHTTP.UseEnvFallback {
		t.Error("explicit use_env_fallback=false in TOML must keep env fallback disabled")
	}
}

func TestUseEnvFallback_OmittedTOMLPreservesPreset(t *testing.T) {
	// [outbound_http] section present but use_env_fallback not set;
	// the strict preset value (false) must be preserved.
	// Clear ambient env override so the preset default is not silently flipped.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
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
	if cfg.OutboundHTTP.UseEnvFallback {
		t.Error("omitted use_env_fallback in TOML must preserve the strict preset default (false)")
	}
}

func TestUseEnvFallback_ProxyURLPrecedence(t *testing.T) {
	// When proxy_url is set alongside use_env_fallback=true, both fields
	// may coexist in the config contract; proxy_url takes precedence at the
	// HTTP client level (env vars are not consulted when an explicit URL is set).
	// Clear ambient env override so the TOML coexistence is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"

[outbound_http]
proxy_url = "http://explicit.proxy:8080"
use_env_fallback = true
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
	if !cfg.OutboundHTTP.UseEnvFallback {
		t.Error("use_env_fallback should remain true when proxy_url is also set")
	}
}

func TestOutboundHTTPConfigStrict_UseEnvFallbackFalse(t *testing.T) {
	// OutboundHTTPConfigStrict is a non-ambient building block: it must never
	// enable environment-based proxy discovery on its own. StrictConfig() now
	// also defaults use_env_fallback=false, so the raw builder must stay false
	// so callers that use it directly get a safe, non-ambient default.
	cfg := OutboundHTTPConfigStrict()
	if cfg.UseEnvFallback {
		t.Error("OutboundHTTPConfigStrict() must return UseEnvFallback=false (non-ambient by default)")
	}
}

func TestUseEnvFallback_EnvOverrideOptsIn(t *testing.T) {
	// OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK=true overrides the strict
	// preset default and opts in to ambient proxy discovery.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "true")
	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.OutboundHTTP.UseEnvFallback {
		t.Error("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK=true must opt in to env fallback")
	}
}

func TestUseEnvFallback_EnvOverrideOptsOut(t *testing.T) {
	// OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK=false keeps env fallback
	// disabled even when an explicit TOML opt-in is present.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "dev"

[outbound_http]
use_env_fallback = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "false")
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OutboundHTTP.UseEnvFallback {
		t.Error("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK=false must override TOML opt-in")
	}
}

func TestUseEnvFallback_EnvOverrideInvalid(t *testing.T) {
	// Invalid env var values are rejected during load.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "not-a-bool")
	_, err := Load(LoaderOptions{})
	if err == nil {
		t.Fatal("Load() expected error for invalid env var value, got nil")
	}
}
