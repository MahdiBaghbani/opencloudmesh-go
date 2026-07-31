// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMustInviteEnforced_NilSemantics(t *testing.T) {
	falseVal := false
	trueVal := true

	tests := []struct {
		name string
		cfg  OCMConfig
		want bool
	}{
		{name: "nil invite section defaults to enabled", cfg: OCMConfig{}, want: true},
		{name: "nil enforce knob defaults to enabled", cfg: OCMConfig{Invite: &InviteConfig{}}, want: true},
		{name: "explicit true is enabled", cfg: OCMConfig{Invite: &InviteConfig{EnforceMustInvite: &trueVal}}, want: true},
		{name: "explicit false is the opt-out", cfg: OCMConfig{Invite: &InviteConfig{EnforceMustInvite: &falseVal}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.MustInviteEnforced(); got != tt.want {
				t.Errorf("MustInviteEnforced() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoad_OCMInvite_DefaultUnsetEnforced(t *testing.T) {
	// Clear ambient env override so the default load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.OCM.MustInviteEnforced() {
		t.Error("must-invite enforcement must default to enabled when [ocm.invite] is unset")
	}
}

func TestLoad_OCMInvite_ExplicitFalseOptOut(t *testing.T) {
	// Clear ambient env override so the opt-out load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"

[ocm.invite]
enforce_must_invite = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.OCM.MustInviteEnforced() {
		t.Error("explicit enforce_must_invite = false must disable must-invite enforcement")
	}
}

func TestLoad_OCMInvite_ExplicitTrue(t *testing.T) {
	// Clear ambient env override so the explicit-true load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"

[ocm.invite]
enforce_must_invite = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.OCM.MustInviteEnforced() {
		t.Error("explicit enforce_must_invite = true must keep must-invite enforcement enabled")
	}
}

func TestLoad_OCMInvite_StrictModeRejectsDisabledEnforcement(t *testing.T) {
	// Clear ambient env override so the validation error path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[ocm.invite]
enforce_must_invite = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("Load() should fail for strict mode with must-invite enforcement disabled")
	}

	if !strings.Contains(err.Error(), "enforce_must_invite") {
		t.Fatalf("expected enforce_must_invite error, got: %v", err)
	}
}

func TestLoad_OCMInvite_StrictModeAllowsDefaultAndExplicitTrue(t *testing.T) {
	// Clear ambient env override so the strict-mode acceptance path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	for name, extra := range map[string]string{
		"default unset": "",
		"explicit true": "[ocm.invite]\nenforce_must_invite = true\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `
mode = "strict"
` + extra
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("write config: %v", err)
			}

			cfg, err := Load(LoaderOptions{ConfigPath: configPath})
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}

			if !cfg.OCM.MustInviteEnforced() {
				t.Error("strict mode must keep must-invite enforcement enabled")
			}
		})
	}
}

func TestLoad_OCMInvite_RejectsUnknownKeys(t *testing.T) {
	// Clear ambient env override so the unknown-key rejection path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"

[ocm.invite]
enforce_must_invite_typo = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("Load() should fail for unknown keys under [ocm.invite]")
	}

	if !strings.Contains(err.Error(), "unsupported keys") {
		t.Fatalf("expected unsupported keys error, got: %v", err)
	}
}
