package config

import (
	"strings"
	"testing"
)

func TestPeerMapping_EmptyTOML_KnobsNil(t *testing.T) {
	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OCM.PeerMapping.IncludesTokenExchangeRequirement != nil ||
		cfg.OCM.PeerMapping.RequiresTokenExchangeRequirement != nil ||
		cfg.OCM.PeerMapping.RequiresHTTPRequestSignatures != nil {
		t.Fatalf("empty TOML must leave peer_compat knobs nil, got %+v", cfg.OCM.PeerMapping)
	}
	if cfg.OCM.PeerMapping.HostPlatform != nil || cfg.OCM.PeerMapping.Platform != nil {
		t.Fatalf("empty TOML must leave peer_compat maps nil, got %+v", cfg.OCM.PeerMapping)
	}
}

func TestPeerMapping_DuplicateHostBindingRejected(t *testing.T) {
	content := `
mode = "dev"

[ocm.peer_compat.host_platform]
"example.com" = "platform-a"

[ocm.peer_compat.platform.platform-a.instance."example.com"]
requires_token_exchange_requirement = false
`
	configPath := writeTempConfig(t, content)
	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject duplicate host binding")
	}
	if !strings.Contains(err.Error(), "duplicate host binding") {
		t.Errorf("error = %v, want duplicate host binding", err)
	}
}

func TestPeerMapping_UnquotedMultiSegmentInstanceRejected(t *testing.T) {
	content := `
mode = "dev"

[ocm.peer_compat.platform.platform-a.instance.example.com]
requires_token_exchange_requirement = false
`
	configPath := writeTempConfig(t, content)
	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject unquoted multi-segment instance host")
	}
	if !strings.Contains(err.Error(), "quoted") {
		t.Errorf("error = %v, want quoted-key error", err)
	}
}

func TestPeerMapping_NormalizesHostKeys(t *testing.T) {
	content := `
mode = "dev"
public_origin = "https://example.com"

[ocm.peer_compat.host_platform]
"host.example:443" = "platform-a"

[ocm.peer_compat.platform.platform-b.instance."other.example:443"]
requires_token_exchange_requirement = false
`
	configPath := writeTempConfig(t, content)
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := cfg.OCM.PeerMapping.HostPlatform["host.example"]; !ok {
		t.Errorf("host_platform key not normalized, got %v", cfg.OCM.PeerMapping.HostPlatform)
	}
	platform := cfg.OCM.PeerMapping.Platform["platform-b"]
	if _, ok := platform.Instance["other.example"]; !ok {
		t.Errorf("instance key not normalized, got %v", platform.Instance)
	}
}

func TestPeerMapping_NormalizedCollisionRejected(t *testing.T) {
	content := `
mode = "dev"
public_origin = "https://example.com"

[ocm.peer_compat.host_platform]
"host.example:443" = "platform-a"
"host.example" = "platform-b"
`
	configPath := writeTempConfig(t, content)
	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject duplicate normalized host")
	}
	if !strings.Contains(err.Error(), "duplicate normalized host") {
		t.Errorf("error = %v, want duplicate normalized host", err)
	}
}

func TestPeerMapping_KnobsLoadAsPointers(t *testing.T) {
	content := `
mode = "dev"

[ocm.peer_compat]
includes_token_exchange_requirement = false
requires_token_exchange_requirement = true
requires_http_request_signatures = true

[ocm.peer_compat.platform.platform-a]
requires_token_exchange_requirement = false

[ocm.peer_compat.platform.platform-a.instance."host.example"]
requires_token_exchange_requirement = false
`
	configPath := writeTempConfig(t, content)
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OCM.PeerMapping.IncludesTokenExchangeRequirement == nil || *cfg.OCM.PeerMapping.IncludesTokenExchangeRequirement {
		t.Errorf("global includes knob = %v, want false", cfg.OCM.PeerMapping.IncludesTokenExchangeRequirement)
	}
	if cfg.OCM.PeerMapping.RequiresTokenExchangeRequirement == nil || !*cfg.OCM.PeerMapping.RequiresTokenExchangeRequirement {
		t.Errorf("global requires-token knob = %v, want true", cfg.OCM.PeerMapping.RequiresTokenExchangeRequirement)
	}
	if cfg.OCM.PeerMapping.RequiresHTTPRequestSignatures == nil || !*cfg.OCM.PeerMapping.RequiresHTTPRequestSignatures {
		t.Errorf("global requires-http-sig knob = %v, want true", cfg.OCM.PeerMapping.RequiresHTTPRequestSignatures)
	}
	platform := cfg.OCM.PeerMapping.Platform["platform-a"]
	if platform.RequiresTokenExchangeRequirement == nil || *platform.RequiresTokenExchangeRequirement {
		t.Errorf("platform requires-token knob = %v, want false", platform.RequiresTokenExchangeRequirement)
	}
	instance := platform.Instance["host.example"]
	if instance.RequiresTokenExchangeRequirement == nil || *instance.RequiresTokenExchangeRequirement {
		t.Errorf("instance requires-token knob = %v, want false", instance.RequiresTokenExchangeRequirement)
	}
	// Platform and instance overlays no longer carry a per-peer HTTP signature knob.
}
