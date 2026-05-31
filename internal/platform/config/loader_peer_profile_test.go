package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_PeerProfileCustomFields(t *testing.T) {
	// Verify custom profile fields still round-trip into config.PeerProfile.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
public_origin = "https://localhost:9200"
mode = "compat"

[peer_profiles.custom_profiles.test_peer]
allow_unsigned_inbound = true
allow_unsigned_outbound = false
allow_mismatched_host = true
allow_http = false
allow_unsigned_discovery = true
token_exchange_quirks = ["accept_plain_token"]
token_exchange_grant_type = "ocm_share"
allowed_basic_auth_patterns = ["token:", "id:token"]
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	profile, ok := cfg.PeerProfiles.CustomProfiles["test_peer"]
	if !ok {
		t.Fatal("expected custom profile 'test_peer' to exist")
	}
	if !profile.AllowUnsignedInbound {
		t.Error("expected AllowUnsignedInbound = true")
	}
	if profile.AllowUnsignedOutbound {
		t.Error("expected AllowUnsignedOutbound = false")
	}
	if !profile.AllowMismatchedHost {
		t.Error("expected AllowMismatchedHost = true")
	}
	if !profile.AllowUnsignedDiscovery {
		t.Error("expected AllowUnsignedDiscovery = true")
	}
	if profile.TokenExchangeGrantType != "ocm_share" {
		t.Errorf("expected TokenExchangeGrantType %q, got %q", "ocm_share", profile.TokenExchangeGrantType)
	}
	if len(profile.AllowedBasicAuthPatterns) != 2 {
		t.Errorf("expected 2 AllowedBasicAuthPatterns, got %d (field not deserialized from TOML)", len(profile.AllowedBasicAuthPatterns))
	} else {
		if profile.AllowedBasicAuthPatterns[0] != "token:" {
			t.Errorf("expected first pattern 'token:', got %q", profile.AllowedBasicAuthPatterns[0])
		}
		if profile.AllowedBasicAuthPatterns[1] != "id:token" {
			t.Errorf("expected second pattern 'id:token', got %q", profile.AllowedBasicAuthPatterns[1])
		}
	}
}
