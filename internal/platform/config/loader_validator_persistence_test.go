// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

func TestLoad_ValidatorMode_RejectsMemoryPersistence(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := `
mode = "validator"

[persistence]
backend = "memory"

[statistics]
enabled = true

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
		t.Fatal("expected Load to reject memory persistence in validator mode")
	}

	if !strings.Contains(err.Error(), "persistence") {
		t.Fatalf("error = %v, want durable persistence validation", err)
	}
}

func TestLoad_ValidatorMode_RejectsJSONPersistence(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := `
mode = "validator"

[persistence]
backend = "json"
data_dir = ".ocm/validator-test"

[statistics]
enabled = true

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
		t.Fatal("expected Load to reject json persistence in validator mode")
	}

	if !errors.Is(err, store.ErrNoSharedSQLiteHandle) {
		t.Fatalf("error = %v, want ErrNoSharedSQLiteHandle", err)
	}
}
