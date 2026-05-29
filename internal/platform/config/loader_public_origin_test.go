package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePublicOrigin_ValidValues(t *testing.T) {
	valid := []struct {
		name   string
		origin string
	}{
		{"https basic", "https://example.com"},
		{"https with trailing slash", "https://example.com/"},
		{"https with port", "https://example.com:8443"},
		{"https with port and trailing slash", "https://example.com:8443/"},
		{"http basic", "http://example.com"},
		{"http with port", "http://example.com:8080"},
		{"https default port explicit", "https://example.com:443"},
		{"http default port explicit", "http://example.com:80"},
		{"localhost", "https://localhost"},
		{"localhost with port", "https://localhost:9200"},
		{"ipv4", "https://192.168.1.1"},
		{"ipv4 with port", "https://192.168.1.1:9200"},
		{"ipv6 bracketed", "https://[::1]"},
		{"ipv6 bracketed with port", "https://[::1]:9200"},
		{"empty skips validation", ""},
	}

	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{PublicOrigin: tt.origin}
			if err := validatePublicOrigin(cfg); err != nil {
				t.Errorf("validatePublicOrigin(%q) unexpected error: %v", tt.origin, err)
			}
		})
	}
}

func TestValidatePublicOrigin_InvalidValues(t *testing.T) {
	tests := []struct {
		name      string
		origin    string
		wantInErr string
	}{
		{
			"no scheme",
			"example.com",
			"must be an absolute URL",
		},
		{
			"ftp scheme",
			"ftp://example.com",
			"scheme must be http or https",
		},
		{
			"has userinfo",
			"https://user:pass@example.com",
			"must not include userinfo",
		},
		{
			"has query",
			"https://example.com?foo=bar",
			"must not include a query string",
		},
		{
			"has fragment",
			"https://example.com#section",
			"must not include a fragment",
		},
		{
			"has base path",
			"https://example.com/app",
			"must not include a path",
		},
		{
			"has deeper path",
			"https://example.com/api/v1",
			"must not include a path",
		},
		{
			"leading whitespace",
			" https://example.com",
			"must not contain leading or trailing whitespace",
		},
		{
			"trailing whitespace",
			"https://example.com ",
			"must not contain leading or trailing whitespace",
		},
		{
			"leading tab",
			"\thttps://example.com",
			"must not contain leading or trailing whitespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{PublicOrigin: tt.origin}
			err := validatePublicOrigin(cfg)
			if err == nil {
				t.Fatalf("validatePublicOrigin(%q) expected error, got nil", tt.origin)
			}
			if !strings.Contains(err.Error(), tt.wantInErr) {
				t.Errorf("validatePublicOrigin(%q) error = %q, want substring %q", tt.origin, err.Error(), tt.wantInErr)
			}
		})
	}
}

func TestLoad_PublicOrigin_InvalidViaConfigFile_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "https://example.com/app"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for public_origin with a path")
	}
	if !strings.Contains(err.Error(), "public_origin") {
		t.Errorf("expected error to mention public_origin, got: %v", err)
	}
}

func TestLoad_ExternalOrigin_UnsupportedFails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
external_origin = "https://example.com"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for unsupported external_origin key")
	}
	if !strings.Contains(err.Error(), "external_origin") {
		t.Errorf("expected error to mention external_origin, got: %v", err)
	}
}

func TestLoad_PublicOrigin_InvalidViaFlag_FailsFast(t *testing.T) {
	origin := "ftp://example.com"
	_, err := Load(LoaderOptions{
		FlagOverrides: FlagOverrides{
			PublicOrigin: &origin,
		},
	})
	if err == nil {
		t.Fatal("expected error for ftp scheme in public_origin")
	}
	if !strings.Contains(err.Error(), "scheme must be http or https") {
		t.Errorf("expected scheme error, got: %v", err)
	}
}

func TestLoad_PublicOrigin_ValidViaConfigFile_Succeeds(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "https://example.com:9200"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.PublicOrigin != "https://example.com:9200" {
		t.Errorf("expected public_origin https://example.com:9200, got %s", cfg.PublicOrigin)
	}
}
