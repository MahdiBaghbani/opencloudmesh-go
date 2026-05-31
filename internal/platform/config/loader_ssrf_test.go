package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocmtest/configfixture"
)

func TestLoad_OldFlatSSRFKey_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[outbound_http]
ssrf_mode = "strict"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for unsupported outbound_http.ssrf_mode key")
	}
	if !strings.Contains(err.Error(), "outbound_http.ssrf_mode") {
		t.Errorf("expected error mentioning outbound_http.ssrf_mode, got: %v", err)
	}
}

func TestLoad_InvalidNestedSSRFMode_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[outbound_http.ssrf]
mode = "block"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid outbound_http.ssrf.mode")
	}
	if !strings.Contains(err.Error(), "invalid outbound_http.ssrf.mode") {
		t.Errorf("expected ssrf.mode error, got: %v", err)
	}
}

func TestLoad_SSRF_NestedSchemaLoads(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "compat"

[outbound_http.ssrf]
mode = "strict"

[outbound_http.ssrf.route_policies.internal]
allow_private_host_suffixes = ["svc.cluster.local"]
allow_private_cidrs = ["10.0.0.0/8"]
allowed_ports = [8080, 8443]
allow_ip_literals = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v (nested SSRF schema should load)", err)
	}

	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Errorf("expected ssrf.mode strict, got %q", cfg.OutboundHTTP.SSRF.Mode)
	}
	policy, ok := cfg.OutboundHTTP.SSRF.RoutePolicies["internal"]
	if !ok {
		t.Fatal("expected route policy 'internal' to be defined")
	}
	if len(policy.AllowPrivateHostSuffixes) != 1 || policy.AllowPrivateHostSuffixes[0] != "svc.cluster.local" {
		t.Errorf("unexpected allow_private_host_suffixes: %v", policy.AllowPrivateHostSuffixes)
	}
	if policy.AllowIPLiterals {
		t.Error("expected allow_ip_literals=false")
	}
}

func TestLoad_SSRF_InvalidRoutePolicyRef_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[outbound_http.ssrf]
mode = "strict"
route_policy = "nonexistent"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid route_policy reference")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("expected error mentioning policy name, got: %v", err)
	}
}

func TestLoad_SSRF_UnsupportedRedirectMode_Fails(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"formerly valid value", "same-host"},
		{"invalid value", "follow-all"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `
[outbound_http.ssrf]
mode = "strict"
redirect_mode = "` + tt.value + `"
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatal("expected error: outbound_http.ssrf.redirect_mode is unsupported")
			}
			if !strings.Contains(err.Error(), "unsupported keys") {
				t.Errorf("expected generic unsupported-keys error, got: %v", err)
			}
			if !strings.Contains(err.Error(), "outbound_http.ssrf.redirect_mode") {
				t.Errorf("expected error mentioning outbound_http.ssrf.redirect_mode, got: %v", err)
			}
		})
	}
}

func TestLoad_SSRF_UnsupportedDNSResolution_Fails(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"formerly valid value", "all-records"},
		{"invalid value", "first-record"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `
[outbound_http.ssrf]
mode = "strict"
dns_resolution = "` + tt.value + `"
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatal("expected error: outbound_http.ssrf.dns_resolution is unsupported")
			}
			if !strings.Contains(err.Error(), "unsupported keys") {
				t.Errorf("expected generic unsupported-keys error, got: %v", err)
			}
			if !strings.Contains(err.Error(), "outbound_http.ssrf.dns_resolution") {
				t.Errorf("expected error mentioning outbound_http.ssrf.dns_resolution, got: %v", err)
			}
		})
	}
}

func TestLoad_SSRF_NoneScope_RejectsOff(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.NoneScopeBase() + configfixture.SSRFOff()
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: compatibility_scope=none must reject ssrf.mode=off")
	}
	if !strings.Contains(err.Error(), "compatibility_scope=none requires outbound_http.ssrf.mode=strict") {
		t.Errorf("expected none+off rejection error, got: %v", err)
	}
}

func TestLoad_SSRF_NoneScope_StrictWithValidRoutePolicy_Loads(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	// strict preset satisfies all compatibility_scope=none guardrails, so
	// a valid route policy under mode=strict must load without error.
	tomlContent := configfixture.NoneScopeBase() +
		configfixture.SSRFStrictWithPolicy("internal") +
		configfixture.RoutePolicyInternal("internal")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v; none + strict + valid route policy must load cleanly", err)
	}
	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Errorf("expected outbound_http.ssrf.mode %q, got %q", "strict", cfg.OutboundHTTP.SSRF.Mode)
	}
	if cfg.OutboundHTTP.SSRF.RoutePolicy != "internal" {
		t.Errorf("expected outbound_http.ssrf.route_policy %q, got %q", "internal", cfg.OutboundHTTP.SSRF.RoutePolicy)
	}
}

func TestLoad_SSRF_NoneScope_RoutePolicyWithIPLiterals_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.NoneScopeBase() +
		configfixture.SSRFStrictWithPolicy("internal") +
		configfixture.RoutePolicyInternalIPLiteralsTrue("internal")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: allow_ip_literals=true forbidden under compatibility_scope=none")
	}
	if !strings.Contains(err.Error(), "allow_ip_literals=false") {
		t.Errorf("expected allow_ip_literals error, got: %v", err)
	}
}

func TestLoad_SSRF_NoneScope_RoutePolicyWithCatchAllCIDR_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.NoneScopeBase() +
		configfixture.SSRFStrictWithPolicy("catchall") +
		configfixture.RoutePolicyCatchAll("catchall")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: catch-all CIDR 0.0.0.0/0 forbidden under compatibility_scope=none")
	}
	if !strings.Contains(err.Error(), "0.0.0.0/0") {
		t.Errorf("expected catch-all CIDR error, got: %v", err)
	}
}

func TestLoad_SSRF_NoneScope_RoutePolicyMissingHostSuffixes_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.NoneScopeBase() +
		configfixture.SSRFStrictWithPolicy("minimal") +
		configfixture.RoutePolicyMinimalNoSuffixes("minimal")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: empty allow_private_host_suffixes forbidden under compatibility_scope=none")
	}
	if !strings.Contains(err.Error(), "allow_private_host_suffixes") {
		t.Errorf("expected host suffixes error, got: %v", err)
	}
}

func TestLoad_SSRF_NoneScope_RoutePolicyWithInvalidCIDR_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.NoneScopeBase() +
		configfixture.SSRFStrictWithPolicy("internal") +
		configfixture.RoutePolicyInternalInvalidCIDR("internal")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: invalid CIDR in allow_private_cidrs should be rejected")
	}
	if !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("expected invalid CIDR error, got: %v", err)
	}
}

func TestLoad_SSRF_NoneScope_RoutePolicyWithInvalidPort_Fails(t *testing.T) {
	tests := []struct {
		name        string
		port        string
		wantContain string
	}{
		{
			name:        "port zero",
			port:        "0",
			wantContain: "invalid port",
		},
		{
			name:        "port above max",
			port:        "65536",
			wantContain: "invalid port",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := configfixture.NoneScopeBase() +
				configfixture.SSRFStrictWithPolicy("internal") +
				configfixture.RoutePolicyInternalWithPort("internal", tc.port)
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatalf("expected error for port %s: should be rejected as out of range", tc.port)
			}
			if !strings.Contains(err.Error(), tc.wantContain) {
				t.Errorf("expected %q in error, got: %v", tc.wantContain, err)
			}
		})
	}
}

func TestSSRFRoutePolicyGuardrails_BlankHostSuffix_NoneScope(t *testing.T) {
	tests := []struct {
		name     string
		suffixes string
	}{
		{"empty string entry", `[""]`},
		{"whitespace-only entry", `["   "]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			tomlContent := `mode = "strict"

[outbound_http.ssrf]
route_policy = "myp"

[outbound_http.ssrf.route_policies.myp]
allow_private_host_suffixes = ` + tt.suffixes + `
allow_private_cidrs = ["10.0.0.0/8"]
allowed_ports = [8080]
allow_ip_literals = false
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatal("expected error for blank entry in allow_private_host_suffixes under compatibility_scope=none")
			}
			if !strings.Contains(err.Error(), "allow_private_host_suffixes") {
				t.Errorf("expected error to mention allow_private_host_suffixes, got: %v", err)
			}
			if !strings.Contains(err.Error(), "compatibility_scope=none") {
				t.Errorf("expected error to mention compatibility_scope=none, got: %v", err)
			}
		})
	}
}

func TestSSRFRoutePolicyGuardrails_BlankHostSuffix_ScopedScope(t *testing.T) {
	tests := []struct {
		name     string
		suffixes string
	}{
		{"empty string entry", `[""]`},
		{"whitespace-only entry", `["   "]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			tomlContent := configfixture.ScopedScopeBase() +
				configfixture.SSRFRoutePolicyRef("myp") +
				configfixture.RoutePolicyWithBlankSuffix("myp", tt.suffixes)
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatal("expected error for blank entry in allow_private_host_suffixes under compatibility_scope=scoped")
			}
			if !strings.Contains(err.Error(), "allow_private_host_suffixes") {
				t.Errorf("expected error to mention allow_private_host_suffixes, got: %v", err)
			}
			if !strings.Contains(err.Error(), "compatibility_scope=scoped") {
				t.Errorf("expected error to mention compatibility_scope=scoped, got: %v", err)
			}
		})
	}
}
