package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/ocm/configfixture"
)

func TestLoad_InvalidCompatibilityScope_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
compatibility_scope = "bogus"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid compatibility_scope")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "invalid compatibility_scope") {
		t.Fatalf("expected invalid compatibility_scope in error, got: %v", err)
	}
	if !strings.Contains(errMsg, "bogus") {
		t.Fatalf("expected bogus in error, got: %v", err)
	}
	if !strings.Contains(errMsg, "must be one of none, scoped") {
		t.Fatalf("expected allowed-values message in error, got: %v", err)
	}
}

func TestLoad_NoneScopeCompatibilityContradictions_FailFast(t *testing.T) {
	tests := []struct {
		name      string
		extra     string
		wantError string
	}{
		{
			name: "none scope requires peer policy strict",
			extra: `
peer_policy = "prefer-strict"
`,
			wantError: "compatibility_scope=none requires peer_policy=strict",
		},
		{
			name: "none scope requires tls not off",
			extra: `
[tls]
mode = "off"
`,
			wantError: "compatibility_scope=none requires tls.mode!=off",
		},
		{
			name: "none scope requires outbound http verify",
			extra: `
[outbound_http]
insecure_skip_verify = true
`,
			wantError: "compatibility_scope=none requires outbound_http.insecure_skip_verify=false",
		},
		{
			name: "none scope requires global enforce when peer trust enabled",
			extra: `
[peer_trust]
enabled = true
config_paths = ["trust-group.json"]

[peer_trust.policy]
global_enforce = false
`,
			wantError: "compatibility_scope=none requires peer_trust.policy.global_enforce=true when peer trust is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			tomlContent := `
mode = "strict"
` + tt.extra
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
				t.Fatalf("expected none-scope contradiction error: %s", tt.wantError)
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

	if cfg.CompatibilityScope != "none" {
		t.Errorf("expected compatibility_scope none, got %q", cfg.CompatibilityScope)
	}
	if cfg.PeerPolicy != "strict" {
		t.Errorf("expected peer_policy strict, got %q", cfg.PeerPolicy)
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

func TestLoad_ScopedCompatibilityRejectsGlobalRelaxations(t *testing.T) {
	tests := []struct {
		name      string
		extra     string
		wantError string
	}{
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

// TestLoad_ScopedCompatibilityAllowsDevFriendlyTransport confirms scoped
// compatibility enforces OCM global posture (signature and peer trust) but
// not transport, so dev-friendly transport settings can coexist with scoped
// compatibility.
func TestLoad_ScopedCompatibilityAllowsDevFriendlyTransport(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := configfixture.ScopedScopeBase() + `
[tls]
mode = "off"

[outbound_http]
insecure_skip_verify = true

[outbound_http.ssrf]
mode = "off"
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
	if cfg.TLS.Mode != "off" {
		t.Errorf("expected tls.mode off to survive under scoped, got %q", cfg.TLS.Mode)
	}
	if !cfg.OutboundHTTP.InsecureSkipVerify {
		t.Error("expected insecure_skip_verify=true to survive under scoped")
	}
	if cfg.OutboundHTTP.SSRF.Mode != "off" {
		t.Errorf("expected outbound_http.ssrf.mode off to survive under scoped, got %q", cfg.OutboundHTTP.SSRF.Mode)
	}
}

func TestLoad_ScopedCompatibilityAllowsPeerScopedRelaxationWiring(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"
compatibility_scope = "scoped"

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
	if len(cfg.PeerProfiles.Mappings) != 1 {
		t.Fatalf("expected one peer profile mapping, got %d", len(cfg.PeerProfiles.Mappings))
	}
}
