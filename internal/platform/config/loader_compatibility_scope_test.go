package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocmtest/configfixture"
)

func TestLoad_StrictModeSignatureContradictions_FailFast(t *testing.T) {
	tests := []struct {
		name      string
		signature string
		wantError string
	}{
		{
			name: "strict mode requires inbound strict",
			signature: `
[signature]
inbound_mode = "lenient"
`,
			wantError: "compatibility_scope=none requires signature.inbound_mode=strict",
		},
		{
			name: "strict mode requires outbound strict",
			signature: `
[signature]
outbound_mode = "criteria-only"
`,
			wantError: "compatibility_scope=none requires signature.outbound_mode=strict",
		},
		{
			name: "strict mode requires peer override off",
			signature: `
[signature]
peer_profile_level_override = "non-strict"
`,
			wantError: "compatibility_scope=none requires signature.peer_profile_level_override=off",
		},
		{
			name: "strict mode requires discovery errors rejected",
			signature: `
[signature]
on_discovery_error = "allow"
`,
			wantError: "compatibility_scope=none requires signature.on_discovery_error=reject",
		},
		{
			name: "strict mode disallows mismatch",
			signature: `
[signature]
allow_mismatch = true
`,
			wantError: "compatibility_scope=none requires signature.allow_mismatch=false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			tomlContent := `
mode = "strict"
` + tt.signature
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatalf("expected strict-mode contradiction error: %s", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("expected %q, got %v", tt.wantError, err)
			}
		})
	}
}

func TestLoad_StrictMode_WithHardenedDefaults_Succeeds(t *testing.T) {
	cfg, err := Load(LoaderOptions{ModeFlag: "strict"})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Signature.InboundMode != "strict" {
		t.Errorf("expected inbound strict, got %q", cfg.Signature.InboundMode)
	}
	if cfg.Signature.OutboundMode != "strict" {
		t.Errorf("expected outbound strict, got %q", cfg.Signature.OutboundMode)
	}
	if cfg.Signature.PeerProfileLevelOverride != "off" {
		t.Errorf("expected peer_profile_level_override off, got %q", cfg.Signature.PeerProfileLevelOverride)
	}
	if cfg.Signature.OnDiscoveryError != "reject" {
		t.Errorf("expected on_discovery_error reject, got %q", cfg.Signature.OnDiscoveryError)
	}
	if cfg.Signature.AllowMismatch {
		t.Error("expected allow_mismatch false")
	}
}

func TestLoad_CrossField_PeerOverrideAllIncompatibleWithStrict(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[signature]
peer_profile_level_override = "all"

[token_exchange]
enabled = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for peer_profile_level_override=all with strict mode")
	}
	if !strings.Contains(err.Error(), "compatibility_scope=none requires signature.peer_profile_level_override=off") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoad_NoneScope_PeerProfileMappingsRejected(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"

[[peer_profiles.mappings]]
pattern = "peer.example.com"
profile = "some-compat"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for peer_profiles.mappings under compatibility_scope=none")
	}
	if !strings.Contains(err.Error(), "compatibility_scope=none forbids peer_profiles.mappings") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoad_NoneScope_CustomProfiles_RelaxingFields_Rejected(t *testing.T) {
	tests := []struct {
		name      string
		extra     string
		wantError string
	}{
		{
			name: "rejects allow_unsigned_inbound",
			extra: `
[peer_profiles.custom_profiles.peer-a]
allow_unsigned_inbound = true
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allow_unsigned_inbound",
		},
		{
			name: "rejects allow_unsigned_outbound",
			extra: `
[peer_profiles.custom_profiles.peer-a]
allow_unsigned_outbound = true
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allow_unsigned_outbound",
		},
		{
			name: "rejects allow_mismatched_host",
			extra: `
[peer_profiles.custom_profiles.peer-a]
allow_mismatched_host = true
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allow_mismatched_host",
		},
		{
			name: "rejects allow_http",
			extra: `
[peer_profiles.custom_profiles.peer-a]
allow_http = true
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allow_http",
		},
		{
			name: "rejects allow_unsigned_discovery",
			extra: `
[peer_profiles.custom_profiles.peer-a]
allow_unsigned_discovery = true
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allow_unsigned_discovery",
		},
		{
			name: "rejects accept_legacy_discovery_public_key",
			extra: `
[peer_profiles.custom_profiles.peer-a]
accept_legacy_discovery_public_key = true
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.accept_legacy_discovery_public_key",
		},
		{
			name: "rejects token_exchange_grant_type",
			extra: `
[peer_profiles.custom_profiles.peer-a]
token_exchange_grant_type = "ocm_share"
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.token_exchange_grant_type",
		},
		{
			name: "rejects token_exchange_quirks",
			extra: `
[peer_profiles.custom_profiles.peer-a]
token_exchange_quirks = ["accept_plain_token"]
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.token_exchange_quirks",
		},
		{
			name: "rejects allowed_basic_auth_patterns",
			extra: `
[peer_profiles.custom_profiles.peer-a]
allowed_basic_auth_patterns = ["token:"]
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allowed_basic_auth_patterns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			tomlContent := `mode = "strict"
` + tt.extra
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatalf("expected none-scope custom profile rejection: %s", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("expected %q, got %v", tt.wantError, err)
			}
		})
	}
}

func TestLoad_NoneScope_RequireTokenExchangeFalse_FailFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
require_token_exchange = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for require_token_exchange=false under compatibility_scope=none")
	}
	if !strings.Contains(err.Error(), "compatibility_scope=none requires require_token_exchange=true") {
		t.Fatalf("expected none-scope require_token_exchange error, got: %v", err)
	}
}

func TestLoad_ScopedCompatibilityRejectsGlobalRelaxations(t *testing.T) {
	tests := []struct {
		name      string
		extra     string
		wantError string
	}{
		{
			name: "rejects inbound lenient",
			extra: `
[signature]
inbound_mode = "lenient"
`,
			wantError: "compatibility_scope=scoped requires signature.inbound_mode=strict",
		},
		{
			name: "rejects outbound token only",
			extra: `
[signature]
outbound_mode = "token-only"
`,
			wantError: "compatibility_scope=scoped requires signature.outbound_mode=strict",
		},
		{
			name: "rejects peer override all",
			extra: `
[signature]
peer_profile_level_override = "all"
`,
			wantError: "compatibility_scope=scoped requires signature.peer_profile_level_override!=all",
		},
		{
			name: "rejects discovery fail open",
			extra: `
[signature]
on_discovery_error = "allow"
`,
			wantError: "compatibility_scope=scoped requires signature.on_discovery_error=reject",
		},
		{
			name: "rejects mismatch allowance",
			extra: `
[signature]
allow_mismatch = true
`,
			wantError: "compatibility_scope=scoped requires signature.allow_mismatch=false",
		},
		{
			name: "rejects tls off",
			extra: `
[tls]
mode = "off"
`,
			wantError: "compatibility_scope=scoped requires tls.mode!=off",
		},
		{
			name: "rejects ssrf off",
			extra: `
[outbound_http.ssrf]
mode = "off"
`,
			wantError: "compatibility_scope=scoped requires outbound_http.ssrf.mode=strict",
		},
		{
			name: "rejects insecure skip verify",
			extra: `
[outbound_http]
insecure_skip_verify = true
`,
			wantError: "compatibility_scope=scoped requires outbound_http.insecure_skip_verify=false",
		},
		{
			name: "rejects fail open peer trust",
			extra: `
[peer_trust]
enabled = true
config_paths = ["trust-group.json"]

[peer_trust.policy]
global_enforce = false
`,
			wantError: "compatibility_scope=scoped requires peer_trust.policy.global_enforce=true when peer trust is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			tomlContent := configfixture.ScopedScopeBase() + tt.extra
			if strings.Contains(tt.extra, "[peer_trust]") {
				trustGroupPath := filepath.Join(dir, "trust-group.json")
				if err := os.WriteFile(trustGroupPath, []byte(`{}`), 0644); err != nil {
					t.Fatalf("failed to write trust group fixture: %v", err)
				}
				tomlContent = strings.ReplaceAll(tomlContent, "trust-group.json", trustGroupPath)
			}
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatalf("expected scoped compatibility error: %s", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("expected %q, got %v", tt.wantError, err)
			}
		})
	}
}

func TestLoad_ScopedCompatibilityAllowsPeerScopedRelaxationWiring(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"
compatibility_scope = "scoped"

[signature]
peer_profile_level_override = "non-strict"

[[peer_profiles.mappings]]
pattern = "peer.example.com"
profile = "compat"

[peer_profiles.custom_profiles.compat]
allow_mismatched_host = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() unexpected error = %v", err)
	}

	if cfg.CompatibilityScope != "scoped" {
		t.Fatalf("expected compatibility_scope scoped, got %q", cfg.CompatibilityScope)
	}
	if cfg.Signature.PeerProfileLevelOverride != "non-strict" {
		t.Fatalf("expected peer_profile_level_override non-strict, got %q", cfg.Signature.PeerProfileLevelOverride)
	}
}
