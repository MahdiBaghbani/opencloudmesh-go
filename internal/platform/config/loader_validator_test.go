// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoad_ValidatorToml(t *testing.T) { //nolint:cyclop // validator.toml load covers many preset fields in one integration read
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	configPath := filepath.Join("..", "..", "..", "configs", "validator.toml")

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Mode != string(ModeValidator) {
		t.Errorf("Mode = %q, want validator", cfg.Mode)
	}

	if cfg.Persistence.DataDir != DefaultValidatorPersistenceDataDir {
		t.Errorf(
			"Persistence.DataDir = %q, want %q",
			cfg.Persistence.DataDir,
			DefaultValidatorPersistenceDataDir,
		)
	}

	if !cfg.Statistics.Enabled {
		t.Error("expected statistics.enabled=true")
	}

	bucket, err := StartPublicRatelimitProfile(cfg)
	if err != nil {
		t.Fatalf("StartPublicRatelimitProfile: %v", err)
	}

	if validateErr := validateCompleteRatelimitBucket(
		bucket,
		"http.interceptors.ratelimit.profiles.scan_public.start_public",
	); validateErr != nil {
		t.Fatalf("validateCompleteRatelimitBucket: %v", validateErr)
	}

	requests, err := positiveInt64Field(
		bucket["requests_per_window"],
		"http.interceptors.ratelimit.profiles.scan_public.start_public.requests_per_window",
	)
	if err != nil {
		t.Fatalf("requests_per_window: %v", err)
	}

	if requests != 10 {
		t.Errorf("requests_per_window = %d, want 10", requests)
	}

	window, err := positiveIntField(
		bucket["window_seconds"],
		"http.interceptors.ratelimit.profiles.scan_public.start_public.window_seconds",
	)
	if err != nil {
		t.Fatalf("window_seconds: %v", err)
	}

	if window != 60 {
		t.Errorf("window_seconds = %d, want 60", window)
	}

	wantTrustedProxies := []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	if len(cfg.Server.TrustedProxies) != len(wantTrustedProxies) {
		t.Fatalf(
			"TrustedProxies len = %d, want %d (%v)",
			len(cfg.Server.TrustedProxies),
			len(wantTrustedProxies),
			cfg.Server.TrustedProxies,
		)
	}

	seen := make(map[string]struct{}, len(wantTrustedProxies))
	for _, cidr := range wantTrustedProxies {
		seen[cidr] = struct{}{}
	}

	for _, cidr := range cfg.Server.TrustedProxies {
		if _, ok := seen[cidr]; !ok {
			t.Errorf("unexpected trusted proxy %q", cidr)
		}

		delete(seen, cidr)
	}

	for cidr := range seen {
		t.Errorf("missing trusted proxy %q", cidr)
	}
}

func TestLoad_ValidatorMode_RejectsBadTrustedProxy(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := `
mode = "validator"

[persistence]
backend = "sqlite"
data_dir = ".ocm/validator-test"

[statistics]
enabled = true

[server]
trusted_proxies = ["not-a-cidr"]

[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 60

[http.services.validator.ratelimit]
profile = "scan_public"
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject invalid trusted proxy in validator mode")
	}

	if !strings.Contains(err.Error(), "trusted_proxies") {
		t.Errorf("error = %v, want trusted_proxies validation", err)
	}
}

func TestValidatorConfig_PresetDefaults(t *testing.T) {
	t.Parallel()

	cfg := ValidatorConfig()

	if cfg.Mode != string(ModeValidator) {
		t.Errorf("Mode = %q, want validator", cfg.Mode)
	}

	if !cfg.Statistics.Enabled {
		t.Error("expected statistics.enabled=true in validator preset")
	}

	if cfg.Persistence.DataDir != DefaultValidatorPersistenceDataDir {
		t.Errorf(
			"Persistence.DataDir = %q, want %q",
			cfg.Persistence.DataDir,
			DefaultValidatorPersistenceDataDir,
		)
	}

	if cfg.Persistence.Backend != BackendSQLite {
		t.Errorf("Persistence.Backend = %q, want %q", cfg.Persistence.Backend, BackendSQLite)
	}

	if _, err := StartPublicRatelimitProfile(cfg); err != nil {
		t.Fatalf("StartPublicRatelimitProfile: %v", err)
	}
}

func TestLoad_ValidatorMode_RejectsStatisticsDisabled(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := `
mode = "validator"

[persistence]
backend = "sqlite"
data_dir = ".ocm/validator-test"

[statistics]
enabled = false

[server]
trusted_proxies = ["127.0.0.0/8"]

[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 60

[http.services.validator.ratelimit]
profile = "scan_public"
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject statistics.enabled=false in validator mode")
	}

	if !strings.Contains(err.Error(), "statistics.enabled") {
		t.Fatalf("error = %v, want statistics.enabled validation", err)
	}
}

func TestDefaultValidatorTrustedProxies_IncludesDockerBridge(t *testing.T) {
	t.Parallel()

	if !slices.Contains(DefaultValidatorTrustedProxies, "172.16.0.0/12") {
		t.Fatal("expected DefaultValidatorTrustedProxies to include 172.16.0.0/12")
	}
}
