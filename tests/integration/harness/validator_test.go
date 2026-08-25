// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package harness

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestApplyValidatorHarnessConfig_SetsStrictSSRF(t *testing.T) {
	t.Parallel()

	cfg := config.DevConfig()
	if cfg.OutboundHTTP.SSRF.Mode == "strict" {
		t.Fatal("precondition: DevConfig outbound SSRF must start off")
	}

	applyValidatorHarnessConfig(cfg, t.TempDir())

	if cfg.Mode != string(config.ModeValidator) {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, config.ModeValidator)
	}

	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Fatalf("OutboundHTTP.SSRF.Mode = %q, want strict", cfg.OutboundHTTP.SSRF.Mode)
	}

	if !cfg.Validator.ActiveEnabled() {
		t.Fatal("validator harness config must keep ActiveEnabled at the default true")
	}

	if err := config.ValidateValidatorModeStartupGuardrails(cfg); err != nil {
		t.Fatalf("harness validator overlay must satisfy validator-mode guardrails: %v", err)
	}
}

func TestPassiveOnlyOverlay_DisablesActiveLegs(t *testing.T) {
	t.Parallel()

	cfg := config.DevConfig()
	applyValidatorHarnessConfig(cfg, t.TempDir())

	enabled := false
	cfg.Validator.Active.Enabled = &enabled

	if cfg.Validator.ActiveEnabled() {
		t.Fatal("passive-only overlay must set ActiveEnabled=false")
	}

	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Fatalf("OutboundHTTP.SSRF.Mode = %q, want strict", cfg.OutboundHTTP.SSRF.Mode)
	}
}
