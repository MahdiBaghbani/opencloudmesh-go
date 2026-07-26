package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoggingConfig_DefaultsPerMode(t *testing.T) {
	// Strict mode defaults to info level
	strictCfg := StrictConfig()
	if strictCfg.Logging.Level != "info" {
		t.Errorf("expected strict mode logging.level 'info', got %q", strictCfg.Logging.Level)
	}

	// Dev mode defaults to debug level
	devCfg := DevConfig()
	if devCfg.Logging.Level != "debug" {
		t.Errorf("expected dev mode logging.level 'debug', got %q", devCfg.Logging.Level)
	}
}

func TestLoad_LoggingConfig_FromTOML(t *testing.T) {
	// Clear ambient env override so the logging load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[logging]
level = "warn"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Logging.Level != "warn" {
		t.Errorf("expected logging.level 'warn', got %q", cfg.Logging.Level)
	}
}

func TestLoad_LoggingConfig_FlagsOverrideTOML(t *testing.T) {
	// Clear ambient env override so the flag-over-TOML precedence is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[logging]
level = "warn"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	logLevel := "error"

	cfg, err := Load(LoaderOptions{
		ConfigPath: configPath,
		FlagOverrides: FlagOverrides{
			LoggingLevel: &logLevel,
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Logging.Level != "error" {
		t.Errorf("expected logging.level 'error' from flag, got %q", cfg.Logging.Level)
	}
}

func TestLoad_LoggingConfig_InvalidLevel_FailsFast(t *testing.T) {
	// Clear ambient env override so the validation error path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[logging]
level = "verbose"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid logging.level")
	}

	if !strings.Contains(err.Error(), "invalid logging.level") {
		t.Errorf("expected logging.level error, got: %v", err)
	}
}

func TestLoad_LoggingConfig_AllValidLevels(t *testing.T) {
	validLevels := []string{"trace", "debug", "info", "warn", "error"}

	for _, level := range validLevels {
		t.Run(level, func(t *testing.T) {
			// Clear ambient env override so each level load is deterministic.
			t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `
mode = "strict"

[logging]
level = "` + level + `"
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			cfg, err := Load(LoaderOptions{ConfigPath: configPath})
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}

			if cfg.Logging.Level != level {
				t.Errorf("expected logging.level %q, got %q", level, cfg.Logging.Level)
			}
		})
	}
}
