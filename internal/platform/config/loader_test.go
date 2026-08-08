// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestConfig_Redacted(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Mode:         "strict",
		PublicOrigin: "https://example.com",
		Server: ServerConfig{
			TrustedProxies: []string{"127.0.0.0/8"},
			BootstrapAdmin: BootstrapAdminConfig{
				Username: "admin",
				Password: "supersecret",
			},
		},
		Signature: DefaultSignatureConfig(),
	}

	redacted := cfg.Redacted()

	if strings.Contains(redacted, "supersecret") {
		t.Error("password was not redacted")
	}

	if !strings.Contains(redacted, "[REDACTED]") {
		t.Error("expected [REDACTED] placeholder")
	}

	if !strings.Contains(redacted, "admin") {
		t.Error("username should be visible")
	}

	if !strings.Contains(redacted, "TokenExchange:") {
		t.Error("expected token exchange block in redacted output")
	}
}

func TestLoad_StrictModeSignatureIETFDefaults(t *testing.T) {
	// Clear ambient env override so the strict-mode signature load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	cfg, err := Load(LoaderOptions{ModeFlag: "strict"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Signature.Label != DefaultSignatureLabel {
		t.Fatalf("Label = %q, want %q", cfg.Signature.Label, DefaultSignatureLabel)
	}

	if len(cfg.Signature.AllowedAlgorithms) != len(sigalg.DefaultAllowed()) || cfg.Signature.AllowedAlgorithms[0] != "ed25519" {
		t.Fatalf("AllowedAlgorithms = %v", cfg.Signature.AllowedAlgorithms)
	}
}
