// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package federation

import (
	"testing"
)

func TestProfileRegistry_GetProfile_ExactMatch(t *testing.T) {
	mappings := []ProfileMapping{
		{Pattern: "nextcloud.example.com", ProfileName: "nextcloud"},
		{Pattern: "owncloud.example.com", ProfileName: "owncloud"},
	}
	reg := NewProfileRegistry(nil, mappings)

	profile := reg.GetProfile("nextcloud.example.com")
	if profile.Name != "nextcloud" {
		t.Errorf("expected nextcloud profile, got %s", profile.Name)
	}

	profile = reg.GetProfile("owncloud.example.com")
	if profile.Name != "owncloud" {
		t.Errorf("expected owncloud profile, got %s", profile.Name)
	}
}

func TestProfileRegistry_GetProfile_WildcardSuffix(t *testing.T) {
	mappings := []ProfileMapping{
		{Pattern: "*.nextcloud.com", ProfileName: "nextcloud"},
	}
	reg := NewProfileRegistry(nil, mappings)

	// Should match subdomain
	profile := reg.GetProfile("cloud.nextcloud.com")
	if profile.Name != "nextcloud" {
		t.Errorf("expected nextcloud profile for cloud.nextcloud.com, got %s", profile.Name)
	}

	// Should match deeper subdomain
	profile = reg.GetProfile("my.cloud.nextcloud.com")
	// Note: filepath.Match doesn't handle multi-level by default,
	// but our special case for *.domain.com handles suffix matching
	if profile.Name != "nextcloud" {
		t.Errorf("expected nextcloud profile for my.cloud.nextcloud.com, got %s", profile.Name)
	}

	// Should NOT match the bare domain
	profile = reg.GetProfile("nextcloud.com")
	if profile.Name != "strict" {
		t.Errorf("expected strict (default) profile for nextcloud.com, got %s", profile.Name)
	}
}

func TestProfileRegistry_GetProfile_NoMatch_DefaultsToStrict(t *testing.T) {
	mappings := []ProfileMapping{
		{Pattern: "known.example.com", ProfileName: "nextcloud"},
	}
	reg := NewProfileRegistry(nil, mappings)

	// Unknown domain should get strict profile
	profile := reg.GetProfile("unknown.example.com")
	if profile.Name != "strict" {
		t.Errorf("expected strict profile for unknown domain, got %s", profile.Name)
	}
}

func TestProfileRegistry_GetProfile_CaseInsensitive(t *testing.T) {
	mappings := []ProfileMapping{
		{Pattern: "Nextcloud.Example.COM", ProfileName: "nextcloud"},
	}
	reg := NewProfileRegistry(nil, mappings)

	profile := reg.GetProfile("nextcloud.example.com")
	if profile.Name != "nextcloud" {
		t.Errorf("expected nextcloud profile, got %s", profile.Name)
	}

	profile = reg.GetProfile("NEXTCLOUD.EXAMPLE.COM")
	if profile.Name != "nextcloud" {
		t.Errorf("expected nextcloud profile for uppercase, got %s", profile.Name)
	}
}

func TestProfileRegistry_GetProfile_StripsPort(t *testing.T) {
	mappings := []ProfileMapping{
		{Pattern: "nextcloud.example.com", ProfileName: "nextcloud"},
	}
	reg := NewProfileRegistry(nil, mappings)

	// Should match even with port
	profile := reg.GetProfile("nextcloud.example.com:443")
	if profile.Name != "nextcloud" {
		t.Errorf("expected nextcloud profile with port, got %s", profile.Name)
	}
}

func TestProfileRegistry_GetProfile_FirstMatchWins(t *testing.T) {
	mappings := []ProfileMapping{
		{Pattern: "cloud.example.com", ProfileName: "owncloud"},  // First match
		{Pattern: "*.example.com", ProfileName: "nextcloud"},      // Would also match
	}
	reg := NewProfileRegistry(nil, mappings)

	profile := reg.GetProfile("cloud.example.com")
	if profile.Name != "owncloud" {
		t.Errorf("expected first match (owncloud), got %s", profile.Name)
	}
}

func TestProfileRegistry_CustomProfiles(t *testing.T) {
	customProfiles := map[string]*Profile{
		"custom": {
			Name:                  "custom",
			AllowUnsignedInbound:  true,
			AllowUnsignedOutbound: false,
			TokenExchangeQuirks:   []string{"custom_quirk"},
		},
	}
	mappings := []ProfileMapping{
		{Pattern: "custom.example.com", ProfileName: "custom"},
	}
	reg := NewProfileRegistry(customProfiles, mappings)

	profile := reg.GetProfile("custom.example.com")
	if profile.Name != "custom" {
		t.Errorf("expected custom profile, got %s", profile.Name)
	}
	if !profile.AllowUnsignedInbound {
		t.Error("expected AllowUnsignedInbound to be true")
	}
	if profile.AllowUnsignedOutbound {
		t.Error("expected AllowUnsignedOutbound to be false")
	}
}

func TestProfile_HasQuirk(t *testing.T) {
	profile := &Profile{
		Name: "test",
		TokenExchangeQuirks: []string{
			"accept_plain_token",
			"skip_digest_validation",
		},
	}

	if !profile.HasQuirk("accept_plain_token") {
		t.Error("expected HasQuirk to return true for accept_plain_token")
	}
	if !profile.HasQuirk("skip_digest_validation") {
		t.Error("expected HasQuirk to return true for skip_digest_validation")
	}
	if profile.HasQuirk("nonexistent_quirk") {
		t.Error("expected HasQuirk to return false for nonexistent quirk")
	}
}

func TestBuiltinProfiles_Exist(t *testing.T) {
	profiles := BuiltinProfiles()

	expectedProfiles := []string{"strict", "nextcloud", "owncloud", "dev"}
	for _, name := range expectedProfiles {
		if _, ok := profiles[name]; !ok {
			t.Errorf("expected builtin profile %q to exist", name)
		}
	}
}

func TestBuiltinProfiles_StrictIsDefault(t *testing.T) {
	strict := BuiltinProfiles()["strict"]

	if strict.AllowUnsignedInbound {
		t.Error("strict profile should not allow unsigned inbound")
	}
	if strict.AllowUnsignedOutbound {
		t.Error("strict profile should not allow unsigned outbound")
	}
	if strict.AllowMismatchedHost {
		t.Error("strict profile should not allow mismatched host")
	}
	if strict.AllowHTTP {
		t.Error("strict profile should not allow HTTP")
	}
	if len(strict.TokenExchangeQuirks) > 0 {
		t.Error("strict profile should have no quirks")
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"example.com:443", "example.com"},
		{"example.com.", "example.com"},
		{"Example.COM:8443", "example.com"},
		{"[::1]:8080", "[::1]"}, // IPv6 with port - port stripped
	}

	for _, tt := range tests {
		result := normalizeDomain(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeDomain(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		domain  string
		match   bool
	}{
		// Exact match
		{"example.com", "example.com", true},
		{"example.com", "other.com", false},

		// Case insensitive
		{"Example.COM", "example.com", true},

		// Wildcard suffix
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "deep.sub.example.com", true},
		{"*.example.com", "example.com", false},

		// No match
		{"specific.example.com", "other.example.com", false},
	}

	for _, tt := range tests {
		result := matchPattern(tt.pattern, tt.domain)
		if result != tt.match {
			t.Errorf("matchPattern(%q, %q) = %v, expected %v", tt.pattern, tt.domain, result, tt.match)
		}
	}
}
