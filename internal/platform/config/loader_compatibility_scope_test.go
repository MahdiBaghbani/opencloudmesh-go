package config

import (
	"strings"
	"testing"
)

func TestLoad_CompatibilityScope_DefaultGlobal(t *testing.T) {
	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OCM.CompatibilityScope != CompatibilityScopeGlobal {
		t.Errorf("CompatibilityScope = %q, want %q", cfg.OCM.CompatibilityScope, CompatibilityScopeGlobal)
	}
}

func TestLoad_CompatibilityScope_ScopedFromFile(t *testing.T) {
	content := `
mode = "dev"

[ocm]
compatibility_scope = "scoped"
`
	configPath := writeTempConfig(t, content)
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OCM.CompatibilityScope != CompatibilityScopeScoped {
		t.Errorf("CompatibilityScope = %q, want %q", cfg.OCM.CompatibilityScope, CompatibilityScopeScoped)
	}
}

func TestLoad_CompatibilityScope_InvalidRejected(t *testing.T) {
	content := `
mode = "dev"

[ocm]
compatibility_scope = "unbounded"
`
	configPath := writeTempConfig(t, content)
	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject invalid compatibility_scope")
	}
	if !strings.Contains(err.Error(), "invalid ocm.compatibility_scope") {
		t.Errorf("error = %v, want compatibility_scope validation", err)
	}
}

func TestLoad_CompatibilityScope_OverlayDoesNotBreakOCMSection(t *testing.T) {
	content := `
mode = "dev"

[ocm]
compatibility_scope = "GLOBAL"

[ocm.peer_compat]
requires_http_request_signatures = true

[ocm.peer_compat.platform.platform-a.instance."host.example"]
requires_token_exchange_requirement = false
`
	configPath := writeTempConfig(t, content)
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OCM.CompatibilityScope != CompatibilityScopeGlobal {
		t.Errorf("CompatibilityScope = %q, want %q", cfg.OCM.CompatibilityScope, CompatibilityScopeGlobal)
	}
	if cfg.OCM.PeerMapping.RequiresHTTPRequestSignatures == nil || !*cfg.OCM.PeerMapping.RequiresHTTPRequestSignatures {
		t.Errorf("global peer_compat requires_http_request_signatures = %v, want true", cfg.OCM.PeerMapping.RequiresHTTPRequestSignatures)
	}
	platform := cfg.OCM.PeerMapping.Platform["platform-a"]
	instance := platform.Instance["host.example"]
	if instance.RequiresTokenExchangeRequirement == nil || *instance.RequiresTokenExchangeRequirement {
		t.Errorf("instance peer_compat requires_token_exchange_requirement = %v, want false", instance.RequiresTokenExchangeRequirement)
	}
	// Per-peer HTTP signature knobs were removed from the overlay structs, so the
	// instance section cannot carry requires_http_request_signatures anymore.
}

func TestLoad_CompatibilityScope_NonCanonicalCasing(t *testing.T) {
	content := `
mode = "dev"

[ocm]
compatibility_scope = "SCOPED"
`
	configPath := writeTempConfig(t, content)
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OCM.CompatibilityScope != CompatibilityScopeScoped {
		t.Errorf("CompatibilityScope = %q, want %q", cfg.OCM.CompatibilityScope, CompatibilityScopeScoped)
	}
}

func TestParseCompatibilityScope(t *testing.T) {
	tests := []struct {
		input   string
		want    CompatibilityScope
		wantErr bool
	}{
		{"global", CompatibilityScopeGlobal, false},
		{"GLOBAL", CompatibilityScopeGlobal, false},
		{"", CompatibilityScopeGlobal, false},
		{"scoped", CompatibilityScopeScoped, false},
		{"none", "", true},
		{"unbounded", "", true},
	}
	for _, tt := range tests {
		got, err := ParseCompatibilityScope(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseCompatibilityScope(%q) expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseCompatibilityScope(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseCompatibilityScope(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
