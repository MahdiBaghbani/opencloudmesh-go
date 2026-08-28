// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"strings"
	"testing"
)

const validatorModeTestBaseTOML = `
mode = "validator"

[persistence]
backend = "sqlite"
data_dir = ".ocm/validator-test"

[statistics]
enabled = true

[server]
trusted_proxies = ["127.0.0.0/8"]

[http.services.validator.ratelimit]
profile = "scan_public"
`

const validatorModeTestBaseWithoutServiceRatelimit = `
mode = "validator"

[persistence]
backend = "sqlite"
data_dir = ".ocm/validator-test"

[statistics]
enabled = true

[server]
trusted_proxies = ["127.0.0.0/8"]
`

func TestLoad_ValidatorMode_AcceptsCompleteStartPublicBucket(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 60
`
	configPath := writeTempConfig(t, tomlContent)

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
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
}

func TestLoad_ValidatorMode_RejectsPartialStartPublicBucket(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject partial start_public bucket")
	}

	if !strings.Contains(err.Error(), "window_seconds") {
		t.Fatalf("error = %v, want window_seconds requirement", err)
	}
}

func TestLoad_ValidatorMode_RejectsNonPositiveStartPublicBucket(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 0
window_seconds = 60
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject non-positive requests_per_window")
	}

	if !strings.Contains(err.Error(), "requests_per_window") {
		t.Fatalf("error = %v, want requests_per_window validation", err)
	}
}

func TestLoad_ValidatorMode_RejectsMissingStartPublicWindowSeconds(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject missing window_seconds")
	}

	if !strings.Contains(err.Error(), "window_seconds") {
		t.Fatalf("error = %v, want window_seconds requirement", err)
	}
}

func TestLoad_ValidatorMode_RejectsMissingStartPublicRequestsPerWindow(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
window_seconds = 60
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject missing requests_per_window")
	}

	if !strings.Contains(err.Error(), "requests_per_window") {
		t.Fatalf("error = %v, want requests_per_window requirement", err)
	}
}

func TestLoad_ValidatorMode_RejectsNonPositiveStartPublicWindowSeconds(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 0
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject non-positive window_seconds")
	}

	if !strings.Contains(err.Error(), "window_seconds") {
		t.Fatalf("error = %v, want window_seconds validation", err)
	}
}

func TestLoad_ValidatorMode_RejectsMissingValidatorRatelimitProfile(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseWithoutServiceRatelimit + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 60

[http.services.validator]
enabled = true
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject missing validator ratelimit profile wiring")
	}

	if !strings.Contains(err.Error(), "http.services.validator.ratelimit") {
		t.Fatalf("error = %v, want validator ratelimit wiring requirement", err)
	}
}

func TestLoad_ValidatorMode_RejectsWrongValidatorRatelimitProfile(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseWithoutServiceRatelimit + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 60

[http.interceptors.ratelimit.profiles.login]
requests_per_window = 5
window_seconds = 30

[http.services.validator.ratelimit]
profile = "login"
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject wrong validator ratelimit profile")
	}

	if !strings.Contains(err.Error(), "http.services.validator.ratelimit.profile must be") {
		t.Fatalf("error = %v, want scan_public profile requirement", err)
	}
}

func TestLoad_ValidatorMode_RejectsMissingStartPublicBucket(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public]
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject missing start_public bucket")
	}

	if !strings.Contains(err.Error(), "missing http.interceptors.ratelimit.profiles.scan_public.start_public") {
		t.Fatalf("error = %v, want missing start_public bucket", err)
	}
}

func TestLoad_ValidatorMode_RejectsNonMapValidatorRatelimit(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseWithoutServiceRatelimit + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 60

[http.services.validator]
ratelimit = "not-a-map"
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject non-map validator ratelimit config")
	}

	if !strings.Contains(err.Error(), "http.services.validator.ratelimit must be a map") {
		t.Fatalf("error = %v, want validator ratelimit map requirement", err)
	}
}

func TestLoad_ValidatorMode_RejectsNonIntegerLimiterFields(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = "ten"
window_seconds = 60
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject non-integer requests_per_window")
	}

	if !strings.Contains(err.Error(), "requests_per_window must be an integer") {
		t.Fatalf("error = %v, want integer requests_per_window validation", err)
	}
}

func TestLoad_ValidatorMode_RejectsMalformedScanPublicProfile(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public]
start_public = "not-a-map"
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject malformed nested scan_public bucket")
	}

	if !strings.Contains(err.Error(), "start_public must be a map") {
		t.Fatalf("error = %v, want nested bucket map requirement", err)
	}
}

func TestLoad_ValidatorMode_RejectsMissingScanPublicProfile(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.other_profile.start_public]
requests_per_window = 10
window_seconds = 60
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject missing scan_public profile")
	}

	if !strings.Contains(err.Error(), "references undefined profile \"scan_public\"") {
		t.Fatalf("error = %v, want undefined scan_public profile reference", err)
	}
}
